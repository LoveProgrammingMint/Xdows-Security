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
using System.Threading.Tasks;
// using Windows.ApplicationModel.Resources;//多语言调用
using Windows.Storage;
using Windows.UI;
using Windows.UI.ViewManagement;
using Windows.UI.WindowManagement;
using WinRT;
using WinUIEx;

namespace Xdows_Security
{
    public sealed partial class MainWindow : Window
    {
        public static string NowPage = "Home";
        //private readonly ResourceLoader _resourceLoader = ResourceLoader.GetForViewIndependentUse(); //多语言调用
        public MainWindow()
        {
            InitializeComponent();
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
            var manager = WinUIEx.WindowManager.Get(window);
            manager.MinWidth = 650;
            manager.MinHeight = 530;
            LogText.AddNewLog(1, "UI Interface", "主窗口加载成功");
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
            if (!App.IsRunAsAdmin())
            {
                TitleText.Text += " (受限模式)";
            }
            BadgeNotificationManager.Current.ClearBadge();
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

            nav.Header = (nav.SelectedItem as NavigationViewItem)?.Content ?? string.Empty;

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
        private NavigationViewItem FindNavigationItemByTag(IList<object> items, string targetTag)
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
            return new();
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
        private string LastBackdrop = "";
        private double LastOpacity = 100;
        private ISystemBackdropControllerWithTargets backdropController;
        private ICompositionSupportsSystemBackdrop backdropTarget;
        private static readonly SystemBackdropConfiguration backdropConfig = new()
        {
            IsInputActive = true,
        };
        public void ApplyBackdrop(string backdropType)
        {
            try {
                if (RootGrid == null) return;
                var settings = ApplicationData.Current.LocalSettings;
                if (LastBackdrop == backdropType && LastOpacity == (Double)settings.Values["AppBackdropOpacity"])
                {
                    return;
                }
                else
                {
                    LastOpacity = (Double)settings.Values["AppBackdropOpacity"];
                    LastBackdrop = backdropType;
                }

                if (backdropType == "Solid")
                {
                    try
                    {
                        this.SystemBackdrop = null;
                        var currentTheme = GetCurrentTheme();
                        if (currentTheme == ElementTheme.Dark)
                        {
                            RootGrid.Background = new SolidColorBrush(Color.FromArgb(0xFF, 0x20, 0x20, 0x20));
                        }
                        else
                        {
                            RootGrid.Background = new SolidColorBrush(Colors.White);
                        }
                    }
                    catch { }
                    return;
                }
                if (!MicaController.IsSupported() &&
                    (backdropType == "Mica" || backdropType == "MicaAlt"))
                {
                    backdropType = "Acrylic";
                }
                try
                {
                    RootGrid.Background = new SolidColorBrush(Colors.Transparent);
                    Microsoft.UI.Xaml.Media.SystemBackdrop? changeSystemBackdrop = null;
                    backdropTarget = this.As<ICompositionSupportsSystemBackdrop>();
                    switch (backdropType)
                    {
                        case "Mica":
                            backdropController = new MicaController()
                            {
                                LuminosityOpacity = (float)LastOpacity / 100
                            };
                            break;
                        case "MicaAlt":
                            changeSystemBackdrop = new MicaBackdrop()
                            {
                                Kind = Microsoft.UI.Composition.SystemBackdrops.MicaKind.BaseAlt
                            };
                            if (this.SystemBackdrop == changeSystemBackdrop) return;
                            this.SystemBackdrop = changeSystemBackdrop;
                            return;
                        case "Acrylic":
                            backdropController = new DesktopAcrylicController()
                            {
                                LuminosityOpacity = (float)LastOpacity / 100
                            };
                            break;
                        default:
                            ApplyBackdrop("Solid");
                            return;
                    }
                    backdropController.AddSystemBackdropTarget(backdropTarget);
                    backdropController.SetSystemBackdropConfiguration(backdropConfig);
                }
                catch { }
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
    }
}
