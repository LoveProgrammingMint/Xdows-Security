using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using Windows.ApplicationModel.Resources;
using Windows.Globalization;
using Windows.Storage;
using Windows.System.UserProfile;

namespace Xdows_Security
{
    public static class LogText 
    {
        private static string? _Text;
        public static string Text { get => _Text ??= String.Empty; set => _Text = value; }

        public static event EventHandler? TextChanged;

        private static readonly int MAXLONG = 8000;

        public static void AddNewLog(int Level, string Source, string Info, bool Update)
        {
            string currentTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"); // 获取当前本地时间
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

            if (Update)
            {
                TextChanged?.Invoke(null, EventArgs.Empty);
            }
        }
    }

    public static class Protection
    {
        public static bool IsOpen() {
            return true;
        }
        public static bool Run(int RunID)
        {
            string RunFileName = RunID switch
            {
                0 => "XIGUASecurityProgress.exe",
                1 => "XIGUASecurityBoot.exe",
                2 => "XIGUASecurityRegister.exe",
                _ => "XIGUASecurityProgress.exe",
            };
            try
            {
                LogText.AddNewLog(1, "Protection", $"Try Running {RunFileName}...", false);
                Process.Start(RunFileName);
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(3, "Protection", ex.Message, false);
                return false;
            }
            return true;
        }
    }

    public partial class App : Application
    {
        public static MainWindow? MainWindow { get; private set; }
        public static string GetCloudApiKey() {return ""; }//想盗用 ApiKey ? 没门

        public App()
        {
            LogText.AddNewLog(1, "UI Interface", "尝试加载主窗口",false);
            this.InitializeComponent();
        }

        protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
            CheckWindowsVersion();
            InitializeLanguage();
            InitializeTheme();
            InitializeBackdrop();

            MainWindow = new MainWindow();

            // 设置主窗口主题
            if (MainWindow.Content is FrameworkElement rootElement)
            {
                rootElement.RequestedTheme = Theme;
            }

            MainWindow.Activate();
        }

        private void InitializeLanguage()
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
                CloseButtonText = _resourceLoader.GetString("CloseButtonText"),
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
        public static bool IsWindows11OrGreater { get; private set; }
        private const string DefaultBackdrop = "Mica";

        private static void CheckWindowsVersion()
        {
            try
            {
                ulong version = ulong.Parse(Windows.System.Profile.AnalyticsInfo.VersionInfo.DeviceFamilyVersion);
                ulong build = (version & 0x00000000FFFF0000L) >> 16;
                IsWindows11OrGreater = build >= 22000; // Windows 11 起始版本号
            }
            catch
            {
                IsWindows11OrGreater = false;
            }
        }

        private static void InitializeBackdrop()
        {
            var settings = ApplicationData.Current.LocalSettings;
            if (!settings.Values.ContainsKey("AppBackdrop"))
            {
                settings.Values["AppBackdrop"] = IsWindows11OrGreater ?
                    DefaultBackdrop : "Acrylic";
            }
        }
    }
}