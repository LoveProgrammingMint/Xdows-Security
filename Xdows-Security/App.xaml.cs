using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Diagnostics;
using System.Linq;
using System.Reflection.Emit;
using Windows.ApplicationModel.Resources;
using Windows.Globalization;
using Windows.Storage;
using Windows.System.UserProfile;

namespace Xdows_Security
{
    public static class LogText
    {
        public static string Text { get; set; } = string.Empty;
        public static event EventHandler? TextChanged;

        public static void AddNewLog(int Level, string Source, string Info, bool Update)
        {
            string currentTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"); // 获取当前本地时间
            string LevelText = "UNKNOWN"; 
            switch (Level)
            {
                case 0:
                    LevelText = "DEBUG";
                    break;
                case 1:
                    LevelText = "INFO";
                    break;
                case 2:
                    LevelText = "WARN";
                    break;
                case 3:
                    LevelText = "ERROR";
                    break;
                case 4:
                    LevelText = "FATAL";
                    break;
                default:
                    LevelText = "UNKNOWN";
                    break;
            }

            string logEntry = $"[{currentTime}][{LevelText}][{Source}]: {Info}{Environment.NewLine}";
            Text += logEntry;

            if (Update) {
                TextChanged?.Invoke(null, EventArgs.Empty);

            }
        }
    }
    public partial class App : Application
    {
        public static MainWindow? MainWindow { get; private set; }

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
            if (settings.Values.TryGetValue("AppLanguage", out object language))
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
                var appPath = Process.GetCurrentProcess().MainModule.FileName;
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

        private void InitializeTheme()
        {
            var settings = ApplicationData.Current.LocalSettings;
            if (settings.Values.TryGetValue("AppTheme", out object theme))
            {
                string themeString = theme as string;
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

        private void CheckWindowsVersion()
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

        private void InitializeBackdrop()
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