// using Windows.ApplicationModel.Resources;//多语言调用
using Compatibility.Windows.Storage;
using Microsoft.UI;
using Microsoft.UI.Composition;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.Windows.BadgeNotifications;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Windows.UI;
using Windows.UI.ViewManagement;
using Windows.UI.WindowManagement;
using WinRT;
using WinUI3Localizer;
using WinUIEx;
using Xdows_Security.ViewModel;

namespace Xdows_Security
{
    public sealed partial class MainWindow : Window
    {
        public static string NowPage = "Home";

        public MainWindow()
        {
            InitializeComponent();
            LogText.AddNewLog(1, "UI Interface", "MainWindow loaded successfully");
            Window window = this;
            window.ExtendsContentIntoTitleBar = true;
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
            var manager = WinUIEx.WindowManager.Get(window);
            manager.MinWidth = 650;
            manager.MinHeight = 530;
            Closed += delegate { Window_Closed(); };
            Localizer.Get().LanguageChanged += OnLangChanged;

        }

        private void MainWindow_Activated_FirstTime(object sender, WindowActivatedEventArgs args)
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
            ApplyBackdrop(backdrop ?? "Mica");
            Activated -= MainWindow_Activated_FirstTime;
            //if (!App.IsRunAsAdmin())
            //{
            //    TitleText.Text += " (受限模式)";
            //}
            UpdateNavTheme(
                settings.Values.TryGetValue("AppNavTheme", out object raw) && raw is double d ?
                (int)d : 0
            );
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
            if (navTheme == 0) {
                if (nav.SettingsItem is NavigationViewItem setting)
                {
                    setting.Content = Localizer.Get().GetLocalizedString("MainWindow_Nav_Settings");
                    nav.Header = (nav.SelectedItem as NavigationViewItem)?.Content ?? string.Empty;
                }
            }
        }
        public void UpdateTheme(ElementTheme selectedTheme)
        {
            App.Theme = selectedTheme;
            var window = App.MainWindow;
            if (window is not null)
            {
                var appWindow = Microsoft.UI.Windowing.AppWindow.GetFromWindowId(
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
        }
        public ApplicationTheme GetSystemTheme()
        {
            var settings = new UISettings();
            var systemBackground = settings.GetColorValue(UIColorType.Background);

            return IsLightColor(systemBackground) ? ApplicationTheme.Light : ApplicationTheme.Dark;
        }
        private bool IsLightColor(Windows.UI.Color color)
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
            else {
                nav.Header = (nav.SelectedItem as NavigationViewItem)?.Content ?? string.Empty;
            }
            NowPage = PageName; 
            switch (PageName)
            {
                case "Home":
                    navContainer.Navigate(typeof(HomePage));
                    break;
                case "Security":
                    navContainer.Navigate(typeof(SecurityPage));
                    break;
                case "Xdows-Tools":
                    navContainer.Navigate(typeof(XdowsToolsPage));
                    break;
                case "Settings":
                    navContainer.Navigate(typeof(SettingsPage));
                    break;
            }
        }
        public void GoToBugReportPage(string? PageName)
        {
            NowPage = "BugReport";
            nav.Header = PageName;
            nav.SelectedItem = null;
            navContainer.Navigate(typeof(BugReportPage));
        }
        private NavigationViewItem? FindNavigationItemByTag(IList<object> items, string targetTag)
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

        public void ApplyBackdrop(string backdropType)
        {
            try {
                if (RootGrid == null) return;

                var settings = ApplicationData.Current.LocalSettings;
                double opacity = settings.Values["AppBackdropOpacity"] is double v ? v : 100;

                if (_lastBackdrop == backdropType && _lastOpacity.Equals(opacity)) return;

                _lastBackdrop = backdropType;
                _lastOpacity = opacity;
                _lastBackdrop = "";
                if (backdropType == "Solid")
                {
                    this.SystemBackdrop = null;
                    RootGrid.Background = GetCurrentTheme() == ElementTheme.Dark
                        ? new SolidColorBrush(Color.FromArgb(0xFF, 0x20, 0x20, 0x20))
                        : new SolidColorBrush(Colors.White);
                    return;
                }
                if (!MicaController.IsSupported() && (backdropType is "Mica" or "MicaAlt"))
                    backdropType = "Acrylic";
                RootGrid.Background = new SolidColorBrush(Colors.Transparent);
                _target = this.As<ICompositionSupportsSystemBackdrop>();

                _controller = backdropType switch
                {
                    "Mica" => new MicaController()
                    {
                        LuminosityOpacity = (float)opacity / 100
                    },
                    "MicaAlt" => new MicaController()
                    {
                        LuminosityOpacity = (float)opacity / 100,
                        Kind = MicaKind.BaseAlt
                    },
                    "Acrylic" => new DesktopAcrylicController()
                    {
                        LuminosityOpacity = (float)opacity / 100
                    },
                    _ => null
                };

                if (_controller == null)
                {
                    ApplyBackdrop("Solid");
                    return;
                }

                _controller.AddSystemBackdropTarget(_target);
                _controller.SetSystemBackdropConfiguration(_config);
            }
            catch { }
        }
        private void OnThemeChanged(FrameworkElement sender, object args)
        {
            var settings = ApplicationData.Current.LocalSettings;
            var backdrop = settings.Values["AppBackdrop"] as string;
            if (backdrop == "Solid")
            {
                ApplyBackdrop(backdrop);
            }
        }

        private void Window_Closed()
        {
            if (_controller == null) return;
            _controller.Dispose();
            _controller = null;
        }

        private void nav_Loaded(object sender, RoutedEventArgs e)
        {
            LoadLocalizerData();
        }
    }
}
