using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Win32;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;
using System;
using System.IO;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Windows.ApplicationModel.Resources;
using Windows.Globalization;
using Windows.Storage;
using Windows.System.UserProfile;
using Xdows.Protection;
using static Xdows.Protection.ProcessProtection;

namespace Xdows_Security
{
    public static class LogText
    {
        private static string? _Text;
        public static string Text { get => _Text ??= String.Empty; set => _Text = value; }

        public static event EventHandler? TextChanged;

        private static readonly int MAXLONG = 8000;

        public static void ClearLog()
        {
            Text = String.Empty;
            AddNewLog(1, "LogSystem", "Log is Clear");
        }

        public static void AddNewLog(int Level, string Source, string Info)
        {
            string currentTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string LevelText = Level switch
            {
                0 => "DEBUG",
                1 => "INFO",
                2 => "WARN",
                3 => "ERROR",
                4 => "FATAL",
                _ => "UNKNOWN",
            };
            string logEntry = $"[{currentTime}][{LevelText}][{Source}]: {Info}{Environment.NewLine}";
            if ((Text + logEntry).Length > MAXLONG)
            {
                Text = logEntry;
            }
            else
            {
                Text += logEntry;
            }

            if (MainWindow.NowPage == "Home")
            {
                TextChanged?.Invoke(null, EventArgs.Empty);
            }
        }
    }
    class Statistics {
        public static int ScansQuantity { get; set; } = 0;
        public static int VirusQuantity { get; set; } = 0;
    }
    public static class Notifications
    {
        public static void ShowNotification(string title, string content)
        {
            AppNotification notification = new AppNotificationBuilder()
                .AddText (title)
                .AddText(content)
                .BuildNotification();
            AppNotificationManager.Default.Show(notification);
        }

    } 
    public static class Protection
    {        public static bool IsOpen()
        {
            return true;
        }
        public static InterceptCallBack interceptCallBack = (bool isSucceed, string path) =>
        {
            LogText.AddNewLog(2, "Protection", isSucceed
                ? $"InterceptProcess：{Path.GetFileName(path)}"
                : $"Cannot InterceptProcess：{Path.GetFileName(path)}");
            string content = isSucceed
                ? $"Xdows Security 已发现威胁.{Environment.NewLine}相关进程：{Path.GetFileName(path)}"
                : $"Xdows Security 无法处理威胁.{Environment.NewLine}相关进程：{Path.GetFileName(path)}";
            Notifications.ShowNotification("发现威胁", content);
        };
        public static bool Run(int RunID)
        {
            if (RunID == 0) {
                if (ProcessProtection.IsEnabled())
                {
                    LogText.AddNewLog(1, "Protection", $"Try to Disable ProcessProtection ...");
                    return Xdows.Protection.ProcessProtection.Disable();
                }
                else 
                {
                    LogText.AddNewLog(1, "Protection", $"Try to Enable ProcessProtection ...");
                    return Xdows.Protection.ProcessProtection.Enable(interceptCallBack);
                }
            }


            string RunFileName = RunID switch
            {
                0 => "XIGUASecurityProgress.exe",
                1 => "XIGUASecurityBoot.exe",
                2 => "XIGUASecurityRegister.exe",
                _ => "XIGUASecurityProgress.exe",
            };
            try
            {
                LogText.AddNewLog(1, "Protection", $"Try to Run {RunFileName}...");
                Process.Start(RunFileName);
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(3, "Protection", ex.Message);
                return false;
            }
            return true;
        }
    }

    public partial class App : Application
    {
        public static MainWindow MainWindow { get; private set; } = new();
        public static string GetCloudApiKey() { return ""; }//想盗用 ApiKey ? 没门
        private bool RequestAdminPrivilegesAsync()
        {
            try
            {
                using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
                {
                    var principal = new System.Security.Principal.WindowsPrincipal(identity);
                    if (principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
                    {
                        return true;
                    }
                }
                ProcessStartInfo startInfo = new ProcessStartInfo()
                {
                    FileName = Environment.ProcessPath,
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                try
                {
                    Process.Start(startInfo);
                    return true;
                }
                catch
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }
        public App()
        {
            LogText.AddNewLog(1, "UI Interface", "尝试加载主窗口");
            if (RequestAdminPrivilegesAsync())
            {
                this.InitializeComponent();
            }
            else
            {
                LogText.AddNewLog(3, "System", "无法获取管理员权限");
                Environment.Exit(0);
            }
        }

        protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
            InitializeLanguage();
            InitializeTheme();
            InitializeBackdrop();
            // 设置主窗口主题
            if (MainWindow.Content is FrameworkElement rootElement)
            {
                rootElement.RequestedTheme = Theme;
            }
            MainWindow.Activate();
        }

        private static void InitializeLanguage()
        {
            var settings = ApplicationData.Current.LocalSettings;
            if (settings.Values.TryGetValue("AppLanguage", out object? language))
            {
                ApplicationLanguages.PrimaryLanguageOverride = language as string;
            }
            else
            {
                var systemLanguage = GlobalizationPreferences.Languages.FirstOrDefault();
                var defaultLanguage = systemLanguage?.StartsWith("zh") ?? false ? "zh-HANS" : "en-US";
                ApplicationLanguages.PrimaryLanguageOverride = defaultLanguage;
                settings.Values["AppLanguage"] = defaultLanguage;
            }
        }

        public static void RestartApplication()
        {
            try
            {
                var appPath = Environment.ProcessPath;
                Process.Start(new ProcessStartInfo
                {
                    FileName = appPath,
                    UseShellExecute = true
                });
                Application.Current.Exit();
            }
            catch (Exception ex)
            {
                ShowErrorDialog("RestartFailedTitle", $"{_resourceLoader.GetString("RestartFailedMessage")}{ex.Message}");
            }
        }

        private static ResourceLoader _resourceLoader = ResourceLoader.GetForViewIndependentUse();

        private static async void ShowErrorDialog(string titleKey, string message)
        {
            if (MainWindow?.Content?.XamlRoot == null) return;

            ContentDialog dialog = new ContentDialog
            {
                Title = _resourceLoader.GetString(titleKey),
                Content = message,
                PrimaryButtonText = _resourceLoader.GetString("RetryButtonText"),
                CloseButtonText = _resourceLoader.GetString("CloseButtonText"),
                RequestedTheme = ((FrameworkElement)MainWindow.Content).RequestedTheme,
                XamlRoot = MainWindow.Content.XamlRoot
            };
            await dialog.ShowAsync().AsTask();
        }
        public static ElementTheme Theme { get; set; } = ElementTheme.Default;

        private static void InitializeTheme()
        {
            var settings = ApplicationData.Current.LocalSettings;
            if (settings.Values.TryGetValue("AppTheme", out object? theme))
            {
                string themeString = theme as string ?? ElementTheme.Default.ToString();
                if (Enum.TryParse(themeString, out ElementTheme themeValue))
                {
                    Theme = themeValue;
                }
            }
            else
            {
                Theme = ElementTheme.Default;
                settings.Values["AppTheme"] = Theme.ToString();
            }
        }


        // 背景材质
        private const string DefaultBackdrop = "Mica";

        protected internal static bool CheckWindowsVersion()
        {
            var version = Environment.OSVersion.Version;
            if (version.Major == 10 && version.Build >= 22000)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private static void InitializeBackdrop()
        {
            var settings = ApplicationData.Current.LocalSettings;
            if (!settings.Values.ContainsKey("AppBackdrop"))
            {
                settings.Values["AppBackdrop"] = CheckWindowsVersion() ?
                    DefaultBackdrop : "Acrylic";
            }
        }
    }
}