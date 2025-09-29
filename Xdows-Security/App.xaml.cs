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
using System.Text.Json;
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

            // NowPage is a static field on MainWindow; check it directly
            if (Xdows_Security.MainWindow.NowPage == "Home")
            {
                TextChanged?.Invoke(null, EventArgs.Empty);
            }
        }
    }
    class Statistics
    {
        public static int ScansQuantity { get; set; } = 0;
        public static int VirusQuantity { get; set; } = 0;
    }
    public static class Notifications
    {
        public static void ShowNotification(string title, string content, string path)
        {
            var builder = new AppNotificationBuilder()
                .AddText(title)
                .AddText(content)
                .AddArgument("action", "openIntercept")
                .AddArgument("path", path);

            AppNotification notification = builder.BuildNotification();
            try
            {
                var markerDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Xdows-Security");
                Directory.CreateDirectory(markerDir);
                var markerPath = Path.Combine(markerDir, "lastNotification.json");
                var markerObj = new
                {
                    action = "openIntercept",
                    path = path,
                    time = DateTime.UtcNow.ToString("o"),
                    content = content
                };
                File.WriteAllText(markerPath, JsonSerializer.Serialize(markerObj));
            }
            catch { }
            AppNotificationManager.Default.Show(notification);
        }

    }
    public static class Protection
    {
        public static bool IsOpen()
        {
            return true;
        }
        public static InterceptCallBack interceptCallBack = (bool isSucceed, string path) =>
        {
            LogText.AddNewLog(2, "Protection", isSucceed
                ? $"InterceptProcess：{Path.GetFileName(path)}"
                : $"Cannot InterceptProcess：{Path.GetFileName(path)}");
            string content = isSucceed ? "已发现威胁" : "无法处理威胁";
            content = $"Xdows Security {content}.{Environment.NewLine}相关数据：{Path.GetFileName(path)}{Environment.NewLine}单击此通知以查看详细信息";
            Notifications.ShowNotification("发现威胁", content, path);
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
        public static MainWindow? MainWindow { get; private set; }
        private static int _mainWindowCreating = 0;
        public static string GetCzkCloudApiKey() { return ""; }
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
        //    Process.Start(startInfo);
        //    Application.Current.Exit();
        //}
        public App()
        {
            LogText.AddNewLog(1, "UI Interface", "尝试加载主窗口");
            try
            {
                AppNotificationManager mgr = AppNotificationManager.Default;
                mgr.NotificationInvoked += OnAppNotificationInvoked;
            }
            catch { }
        }

        private async void OnAppNotificationInvoked(object? sender, AppNotificationActivatedEventArgs e)
        {
            try
            {
                if (e.Arguments is System.Collections.Generic.IDictionary<string, string> argsDict)
                {
                    if (argsDict.TryGetValue("action", out var action) && action == "openIntercept")
                    {
                        string interceptedPath = argsDict.TryGetValue("path", out var path) ? path : string.Empty;
                        LogText.AddNewLog(1, "Notifications", $"Notification invoked with action={action}, path={interceptedPath}");

                        if (MainWindow == null)
                        {
                            if (System.Threading.Interlocked.CompareExchange(ref _mainWindowCreating, 1, 0) == 0)
                            {
                                try
                                {
                                    MainWindow = new MainWindow();
                                }
                                catch (Exception ex)
                                {
                                    LogText.AddNewLog(3, "Notifications", $"Failed to create MainWindow: {ex.Message}");
                                }
                                finally
                                {
                                    System.Threading.Interlocked.Exchange(ref _mainWindowCreating, 0);
                                }
                            }
                            else
                            {
                                await System.Threading.Tasks.Task.Delay(100);
                            }
                        }

                        if (MainWindow != null)
                        {
                            var dq = MainWindow.DispatcherQueue;
                            dq?.TryEnqueue(() =>
                            {
                                try { MainWindow.Activate(); } catch { }
                                try
                                {
                                    InterceptWindow.ShowOrActivate(interceptedPath);
                                }
                                catch (Exception ex)
                                {
                                    LogText.AddNewLog(3, "Notifications", $"Failed to open InterceptWindow: {ex.Message}");
                                }
                            });
                        }
                    }
                }
            }
            catch { }
        }

        protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
            try
            {
                if (!string.IsNullOrEmpty(args.Arguments) && args.Arguments.Contains("openIntercept"))
                {
                    try { MainWindow?.Activate(); } catch { }
                    try
                    {
                        // 从启动参数中解析路径
                        string interceptedPath = string.Empty;
                        var markerResult = TryConsumeNotificationMarker();
                        if (markerResult.exists)
                        {
                            interceptedPath = markerResult.path;
                        }
                        InterceptWindow.ShowOrActivate(interceptedPath);
                    }
                    catch { }
                    return;
                }

                if (string.IsNullOrEmpty(args.Arguments))
                {
                    var markerResult = TryConsumeNotificationMarker();
                    if (markerResult.exists)
                    {
                        try { MainWindow?.Activate(); } catch { }
                        try { InterceptWindow.ShowOrActivate(markerResult.path); } catch { }
                        return;
                    }
                }
            }
            catch { }
            InitializeLanguage();
            InitializeTheme();
            InitializeBackdrop();
            // 确保 MainWindow 已创建后再访问
            if (MainWindow == null)
            {
                MainWindow = new MainWindow();
            }
            // 设置主窗口主题
            if (MainWindow.Content is FrameworkElement rootElement)
            {
                rootElement.RequestedTheme = Theme;
            }
            MainWindow.Activate();

            // InterceptWindow.ShowOrActivate(@"C:\Users\a1b2c\Downloads\MEMZ\MEMZ.exe");// 仅供测试使用，提交前请移除

        }

        private static (bool exists, string path) TryConsumeNotificationMarker()
        {
            try
            {
                var markerDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Xdows-Security");
                var markerPath = Path.Combine(markerDir, "lastNotification.json");
                if (!File.Exists(markerPath)) return (false, string.Empty);

                var txt = File.ReadAllText(markerPath);
                var doc = JsonDocument.Parse(txt);
                string path = string.Empty;
                bool hasAction = false;

                if (doc.RootElement.TryGetProperty("action", out var action) && action.GetString() == "openIntercept")
                {
                    hasAction = true;
                }

                if (doc.RootElement.TryGetProperty("path", out var pathElement))
                {
                    path = pathElement.GetString() ?? string.Empty;
                }

                // 删除标记文件以防重复触发
                try { File.Delete(markerPath); } catch { }

                return (hasAction, path);
            }
            catch { }
            return (false, string.Empty);
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
