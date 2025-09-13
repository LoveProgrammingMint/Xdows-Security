using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.VisualBasic;
using Microsoft.Win32;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Threading.Tasks;
using Windows.ApplicationModel.Resources;
using Windows.Globalization;
using Windows.Storage;
using Windows.System.UserProfile;
using Xdows.Protection;
using static Xdows.Protection.CallBack;
using static Xdows.Protection.FilesProtection;
using static Xdows.Protection.ProcessProtection;
using static Xdows.Protection.RegistryProtection;

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
                ? $"Xdows Security 已发现威胁.{Environment.NewLine}相关数据：{Path.GetFileName(path)}"
                : $"Xdows Security 无法处理威胁.{Environment.NewLine}相关数据：{Path.GetFileName(path)}";
            Notifications.ShowNotification("发现威胁", content);
        };
        public static bool Run(int RunID)
        {
            switch (RunID)
            {
                case 0:
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
                case 1:
                    if (FilesProtection.IsEnabled())
                    {
                        LogText.AddNewLog(1, "Protection", $"Try to Disable FilesProtection ...");
                        return Xdows.Protection.FilesProtection.Disable();
                    }
                    else
                    {
                        LogText.AddNewLog(1, "Protection", $"Try to Enable FilesProtection ...");
                        return Xdows.Protection.FilesProtection.Enable(interceptCallBack);
                    }
                case 4:
                    if (RegistryProtection.IsEnabled())
                    {
                        LogText.AddNewLog(1, "Protection", $"Try to Disable RegistryProtection ...");
                        return Xdows.Protection.RegistryProtection.Disable();
                    }
                    else
                    {
                        LogText.AddNewLog(1, "Protection", $"Try to Enable RegistryProtection ...");
                        return Xdows.Protection.RegistryProtection.Enable(interceptCallBack);
                    }
                default:
                    return false;
            }
        }
    }

    public partial class App : Application
    {
        public static MainWindow MainWindow { get; private set; } = new();
        public static string GetCloudApiKey() { return ""; }//想盗用 ApiKey ? 没门
        public static bool IsRunAsAdmin()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        //public static void RestartAsAdmin()
        //{
        //    var exePath = Process.GetCurrentProcess().MainModule.FileName;
        //    var startInfo = new ProcessStartInfo
        //    {
        //        FileName = exePath,
        //        Verb = "runas",
        //        UseShellExecute = true,
        //        WorkingDirectory = Path.GetDirectoryName(exePath)
        //    };
        //    Process.Start(startInfo);
        //    Application.Current.Exit();
        //}
        public App()
        {
            LogText.AddNewLog(1, "UI Interface", "尝试加载主窗口");
            this.InitializeComponent();
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
                settings.Values["AppBackdrop"] = MicaController.IsSupported() ?
                    DefaultBackdrop : "Acrylic";
            }
        }
    }
}