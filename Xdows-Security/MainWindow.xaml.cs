// using Windows.ApplicationModel.Resources;//多语言调用
using Compatibility.Windows.Storage;
using Microsoft.UI;
using Microsoft.UI.Composition;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Windows.Security.Credentials.UI;
using Windows.UI;
using Windows.UI.ViewManagement;
using Windows.UI.WindowManagement;
using WinRT;
using WinUI3Localizer;
using WinUIEx;

namespace Xdows_Security
{
    public sealed partial class MainWindow : Window
    {
        public static string NowPage = "Home";
        public WinUIEx.WindowManager? manager;

        public MainWindow()
        {
            InitializeComponent();
            manager = WinUIEx.WindowManager.Get(this);
            this.ExtendsContentIntoTitleBar = true;
            AppWindow.SetIcon("logo.ico");
            this.AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
            if (ExtendsContentIntoTitleBar)
            {
                this.SetTitleBar(CustomTitleBar);
            }
            nav.SelectedItem = nav.MenuItems.OfType<NavigationViewItem>().First();
            Activated += MainWindow_Activated_FirstTime;
            Title = AppInfo.AppName;
            TitleText.Text = AppInfo.AppName;
            manager.AppWindow.Closing += MainWindow_Closing;
            manager.MinWidth = 650;
            manager.MinHeight = 530;
            Closed += delegate { Window_Closed(); };
            Localizer.Get().LanguageChanged += OnLangChanged;
            manager.TrayIconContextMenu += (w, e) =>
            {
                var flyout = new MenuFlyout();
                flyout.Items.Add(new MenuFlyoutItem() { Text = Localizer.Get().GetLocalizedString("TrayMenu_Open") });
                flyout.Items.Add(new MenuFlyoutItem() { Text = Localizer.Get().GetLocalizedString("TrayMenu_Settings") });
                flyout.Items.Add(new MenuFlyoutSeparator());
                flyout.Items.Add(new MenuFlyoutItem() { Text = Localizer.Get().GetLocalizedString("TrayMenu_Quit") });
                ((MenuFlyoutItem)flyout.Items[0]).Click += (s, e) => this.Activate();
                ((MenuFlyoutItem)flyout.Items[1]).Click += (s, e) =>
                {
                    this.Activate();
                    this.GoToPage("Settings");
                };
                ((MenuFlyoutItem)flyout.Items[3]).Click += async (s, e) =>
                {
                    if (ApplicationData.Current.LocalSettings.Values.TryGetValue("DisabledVerify", out object? disabledVerify))
                    {
                        if ((bool)disabledVerify)
                        {
                            this.Close();
                            return;
                        }
                        try
                        {
                            var result = await UserConsentVerifier.RequestVerificationAsync(string.Empty);

                            if (result == UserConsentVerificationResult.DeviceNotPresent ||
                            result == UserConsentVerificationResult.DisabledByPolicy ||
                            result == UserConsentVerificationResult.NotConfiguredForUser ||
                            result == UserConsentVerificationResult.Verified)
                            {
                                this.Close();
                            }
                        }
                        catch { }
                    }
                };
                e.Flyout = flyout;
            };
            LogText.AddNewLog(LogLevel.INFO, "UI Interface", "MainWindow loaded successfully");
        }

        private async void MainWindow_Activated_FirstTime(object sender, WindowActivatedEventArgs args)
        {
            var settings = ApplicationData.Current.LocalSettings;

            if (settings.Values.TryGetValue("AppTheme", out object? theme))
            {
                string themeString = theme as string ?? "";
                if (Enum.TryParse(themeString, out ElementTheme themeValue))
                {
                    if (this.Content is FrameworkElement rootElement)
                    {
                        rootElement.RequestedTheme = themeValue;
                    }
                    UpdateTheme(themeValue);
                }
            }
            this.SystemBackdrop = null;
            if (this.Content is Grid grid)
            {
                grid.Background = new SolidColorBrush(Colors.Transparent);
            }

            var backdrop = settings.Values["AppBackdrop"] as string;
            ApplyBackdrop(backdrop ?? "Mica", false);


            if (ApplicationData.HasFile("background_image"))
            {
                var backgroundImagePath = await ApplicationData.ReadFileAsync("background_image");
                if (backgroundImagePath != null)
                {
                    ApplyBackgroundImage(backgroundImagePath);
                }
            }

            Activated -= MainWindow_Activated_FirstTime;
            //if (!App.IsRunAsAdmin())
            //{
            //    TitleText.Text += " (受限模式)";
            //}
            UpdateNavTheme(
                settings.Values.TryGetValue("AppNavTheme", out object raw) && raw is double d ?
                (int)d : 0
            );
            if (settings.Values.TryGetValue("TrayVisibleToggle", out object? trayVisibleToggle))
            {
                manager?.IsVisibleInTray = (bool)trayVisibleToggle;
            }
        }
        public void UpdateNavTheme(int index)
        {
            nav.PaneDisplayMode = index == 0 ? NavigationViewPaneDisplayMode.LeftCompact : NavigationViewPaneDisplayMode.Top;
        }
        private void OnLangChanged(object? sender, LanguageChangedEventArgs e) => LoadLocalizerData();
        private void LoadLocalizerData()
        {
            var settings = ApplicationData.Current.LocalSettings;
            int navTheme = settings.Values.TryGetValue("AppNavTheme", out object raw) && raw is double d ?
                (int)d : 0;
            if (navTheme == 0)
            {
                if (nav.SettingsItem is NavigationViewItem setting)
                {
                    setting.Content = Localizer.Get().GetLocalizedString("MainWindow_Nav_Settings");
                    nav.Header = (nav.SelectedItem as NavigationViewItem)?.Content ?? string.Empty;
                }
            }
        }
        public static void UpdateTheme(ElementTheme selectedTheme)
        {
            App.Theme = selectedTheme;
            var window = App.MainWindow;
            if (window is not null)
            {
                _ = Microsoft.UI.Windowing.AppWindow.GetFromWindowId(
                    Microsoft.UI.Win32Interop.GetWindowIdFromWindow(
                        WinRT.Interop.WindowNative.GetWindowHandle(window)
                    )
                );

                var titleBar = window.AppWindow.TitleBar;
                if (titleBar is not null)
                {
                    if (selectedTheme == ElementTheme.Dark)
                    {
                        titleBar.ButtonForegroundColor = Windows.UI.Color.FromArgb(255, 255, 255, 255);
                    }
                    else if (selectedTheme == ElementTheme.Light)
                    {
                        titleBar.ButtonForegroundColor = Windows.UI.Color.FromArgb(255, 0, 0, 0);
                    }
                    else if (GetSystemTheme() == 0)
                    {

                        titleBar.ButtonForegroundColor = Windows.UI.Color.FromArgb(255, 0, 0, 0);

                    }
                    else
                    {
                        titleBar.ButtonForegroundColor = Windows.UI.Color.FromArgb(255, 255, 255, 255);
                    }
                }
            }
            var settings = ApplicationData.Current.LocalSettings;
            App.MainWindow?.ApplyBackdrop(settings.Values["AppBackdrop"] as string ?? "Mica", true);
        }
        public static ApplicationTheme GetSystemTheme()
        {
            var settings = new UISettings();
            var systemBackground = settings.GetColorValue(UIColorType.Background);

            return IsLightColor(systemBackground) ? ApplicationTheme.Light : ApplicationTheme.Dark;
        }
        private static bool IsLightColor(Windows.UI.Color color)
        {
            double luminance = (0.2126 * color.R + 0.7152 * color.G + 0.0722 * color.B) / 255;
            return luminance > 0.5;
        }
        public void GoToPage(string PageName)
        {
            if ((MD5.HashData(Encoding.UTF8.GetBytes(AppInfo.AppName))[0] >> 4) != 14) return;
            if (PageName == "BugReport")
            {
                GoToBugReportPage(null);
                return;
            }
            var selectedItem = nav.SelectedItem as NavigationViewItem;

            string currentTag = selectedItem?.Tag as string ?? "";

            if (currentTag != PageName)
            {
                var targetItem = FindNavigationItemByTag(nav.MenuItems, PageName);

                if (targetItem == null && nav.SettingsItem != null &&
                    nav.SettingsItem is NavigationViewItem settingsItem &&
                    settingsItem.Tag as string == PageName)
                {
                    targetItem = settingsItem;
                }

                if (targetItem != null)
                {
                    nav.SelectedItem = targetItem;
                    return;
                }
            }

            if (PageName == "Settings")
            {
                nav.Header = Localizer.Get().GetLocalizedString("MainWindow_Nav_Settings");
            }
            else
            {
                nav.Header = (nav.SelectedItem as NavigationViewItem)?.Content ?? string.Empty;
            }
            NowPage = PageName;
            var pageType = PageName switch
            {
                "Home" => typeof(HomePage),
                "Security" => typeof(SecurityPage),
                "Xdows-Tools" => typeof(PluginPage),
                "Settings" => typeof(SettingsPage),
                _ => typeof(HomePage)
            };
            navContainer.Navigate(pageType);
        }
        public void GoToBugReportPage(string? PageName)
        {
            NowPage = "BugReport";
            nav.Header = PageName;
            nav.SelectedItem = null;
            navContainer.Navigate(typeof(BugReportPage));
        }
        private static NavigationViewItem? FindNavigationItemByTag(IList<object> items, string targetTag)
        {
            foreach (var item in items)
            {
                if (item is NavigationViewItem navItem)
                {
                    if (navItem.Tag?.ToString() == targetTag)
                        return navItem;

                    if (navItem.MenuItems.Count > 0)
                    {
                        var childResult = FindNavigationItemByTag(navItem.MenuItems, targetTag);
                        if (childResult != null) return childResult;
                    }
                }
            }
            return null;
        }
        private void NavigationSelectionChanged()
        {
            if (nav.SelectedItem is NavigationViewItem item)
            {
                string pageName = item.Tag as string ?? string.Empty;
                GoToPage(pageName);
            }
        }
        private ElementTheme GetCurrentTheme()
        {
            if (RootGrid.RequestedTheme != ElementTheme.Default)
            {
                return RootGrid.RequestedTheme;
            }

            var settings = new UISettings();
            var systemBackground = settings.GetColorValue(UIColorType.Background);
            return IsLightColor(systemBackground) ? ElementTheme.Light : ElementTheme.Dark;
        }
        private string _lastBackdrop = "";
        private double _lastOpacity = 100;
        private ISystemBackdropControllerWithTargets? _controller;
        private ICompositionSupportsSystemBackdrop? _target;

        private static readonly SystemBackdropConfiguration _config = new()
        {
            IsInputActive = true
        };

        // 背景图片相关字段
        private ImageBrush? _backgroundImageBrush;
        private string? _currentBackgroundImagePath;

        public void ApplyBackdrop(string backdropType, bool compulsory)
        {
            try
            {
                if (RootGrid == null) return;
                var settings = ApplicationData.Current.LocalSettings;
                double opacity = settings.Values["AppBackdropOpacity"] is double v ? v :
                                (settings.Values["AppBackdropOpacity"] is int i ? i : 100);
                if (!compulsory && _lastBackdrop == backdropType && _lastOpacity.Equals(opacity))
                {
                    return;
                }
                CleanupBackdropResources();
                _lastBackdrop = backdropType;
                _lastOpacity = opacity;

                if (backdropType == "Solid")
                {
                    this.SystemBackdrop = null;
                    if (ApplicationData.HasFile("background_image"))
                    {
                        UpdateBackgroundImage();
                    }
                    RootGrid.Background = GetCurrentTheme() == ElementTheme.Dark
                         ? new SolidColorBrush(Color.FromArgb(0xFF, 0x20, 0x20, 0x20))
                         : new SolidColorBrush(Colors.White);
                    return;
                }

                if (backdropType is "Mica" or "MicaAlt" && !MicaController.IsSupported())
                {
                    backdropType = "Acrylic";
                }

                RootGrid.Background = new SolidColorBrush(Colors.Transparent);
                _target = this.As<ICompositionSupportsSystemBackdrop>();

                switch (backdropType)
                {
                    case "Mica":
                        _controller = new MicaController()
                        {
                            LuminosityOpacity = (float)(opacity / 100 * 0.95),
                            TintColor = GetBackgroundColor()
                        };
                        break;
                    case "MicaAlt":
                        _controller = new MicaController()
                        {
                            LuminosityOpacity = (float)(opacity / 100 * 0.95),
                            TintColor = GetBackgroundColor(),
                            Kind = MicaKind.BaseAlt
                        };
                        break;
                    case "Acrylic":
                        _controller = new DesktopAcrylicController()
                        {
                            LuminosityOpacity = (float)(opacity / 100 * 0.95),
                            TintColor = GetBackgroundColor()
                        };
                        break;
                    default:
                        ApplyBackdrop("Solid", compulsory);
                        return;
                }

                if (_controller != null && _target != null)
                {
                    _controller.AddSystemBackdropTarget(_target);
                    _controller.SetSystemBackdropConfiguration(_config);
                }

                // 检查是否有背景图片，如果有则应用
                if (ApplicationData.HasFile("background_image"))
                {
                    UpdateBackgroundImage();

                }
            }
            catch
            {
                ApplyBackdrop("Solid", true);
            }
        }

        private Color GetBackgroundColor()
        {
            return GetCurrentTheme() == ElementTheme.Dark
                ? Color.FromArgb(0xFF, 0x20, 0x20, 0x20)
                : Colors.White;
        }

        private void CleanupBackdropResources()
        {
            if (_controller != null)
            {
                if (_target != null)
                {
                    _controller.RemoveSystemBackdropTarget(_target);
                }
                _controller.Dispose();
                _controller = null;
            }
            _target = null;
        }

        public async void ApplyBackgroundImage(string imagePath)
        {
            try
            {
                _currentBackgroundImagePath = imagePath;

                // 创建ImageBrush
                var bitmapImage = new Microsoft.UI.Xaml.Media.Imaging.BitmapImage();
                var file = await Windows.Storage.StorageFile.GetFileFromPathAsync(imagePath);
                using (var stream = await file.OpenAsync(Windows.Storage.FileAccessMode.Read))
                {
                    await bitmapImage.SetSourceAsync(stream);
                }

                _backgroundImageBrush = new ImageBrush
                {
                    ImageSource = bitmapImage,
                    Stretch = Microsoft.UI.Xaml.Media.Stretch.UniformToFill
                };

                // 获取透明度设置
                var settings = ApplicationData.Current.LocalSettings;
                var opacityValue = settings.Values["AppBackgroundImageOpacity"] as double? ?? 30.0;
                _backgroundImageBrush.Opacity = opacityValue / 100.0;

                // 应用背景图片
                UpdateBackgroundImage();
            }
            catch { }
        }

        public void ClearBackgroundImage()
        {
            try
            {
                _currentBackgroundImagePath = null;
                _backgroundImageBrush = null;
                var settings = ApplicationData.Current.LocalSettings;
                var backdropType = settings.Values["AppBackdrop"] as string ?? "Mica";
                ApplyBackdrop(backdropType, true);
            }
            catch { }
        }

        private void UpdateBackgroundImage()
        {
            if (RootGrid == null || _backgroundImageBrush == null) return;

            try
            {
                // 获取当前背景类型
                var settings = ApplicationData.Current.LocalSettings;
                // 获取透明度设置
                var opacityValue = settings.Values["AppBackgroundImageOpacity"] as double? ?? 30.0;
                _backgroundImageBrush.Opacity = opacityValue / 100.0;
                RootGrid.Background = _backgroundImageBrush;
            }
            catch { }
        }

        public void UpdateBackgroundImageOpacity(double opacity)
        {
            _backgroundImageBrush?.Opacity = opacity;
        }
        private void OnThemeChanged(FrameworkElement sender, object args)
        {
            var settings = ApplicationData.Current.LocalSettings;
            if (settings.Values["AppBackdrop"] is string backdrop)
                ApplyBackdrop(backdrop, true);
        }

        private void Window_Closed()
        {
            if (_controller == null) return;
            _controller.Dispose();
            _controller = null;
        }
        private void MainWindow_Closing(object sender, AppWindowClosingEventArgs e)
        {
            if (ApplicationData.Current.LocalSettings.Values.TryGetValue("TrayVisibleToggle", out object? trayVisibleToggle))
            {
                if ((bool)trayVisibleToggle)
                {
                    e.Cancel = true;
                    this.Hide();
                    return;
                }
            }
            if (ApplicationData.Current.LocalSettings.Values.TryGetValue("DisabledVerify", out object? disabledVerify))
            {
                if (!(bool)disabledVerify)
                {
                    var verifyTask = UserConsentVerifier.RequestVerificationAsync(string.Empty);
                    var result = verifyTask.AsTask().ConfigureAwait(false).GetAwaiter().GetResult();
                    e.Cancel = true;

                    if (result == UserConsentVerificationResult.DeviceNotPresent ||
                    result == UserConsentVerificationResult.DisabledByPolicy ||
                    result == UserConsentVerificationResult.NotConfiguredForUser ||
                    result == UserConsentVerificationResult.Verified)
                    {
                        e.Cancel = false;
                    }
                    return;
                }
            }

        }
        private void Nav_Loaded(object sender, RoutedEventArgs e)
        {
            LoadLocalizerData();
        }
    }
}
