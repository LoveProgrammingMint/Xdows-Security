using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
// using Windows.ApplicationModel.Resources;//多语言调用
using Windows.Storage;
using Windows.UI;
using Windows.UI.ViewManagement;
using Windows.UI.WindowManagement;

namespace Xdows_Security
{
    public sealed partial class MainWindow : Window
    {
        //private readonly ResourceLoader _resourceLoader = ResourceLoader.GetForViewIndependentUse(); //多语言调用
        public MainWindow()
        {
            InitializeComponent();
            Window window = this;
            window.ExtendsContentIntoTitleBar = true;
            AppWindow.SetIcon("logo.ico");
            this.AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
            if (ExtendsContentIntoTitleBar == true)
            {
                this.SetTitleBar(CustomTitleBar);
            }

            nav.SelectedItem = nav.MenuItems.OfType<NavigationViewItem>().First();

            var settings = ApplicationData.Current.LocalSettings;

            // 加载主题设置
            if (settings.Values.TryGetValue("AppTheme", out object theme))
            {
                string themeString = theme as string;
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


            LogText.AddNewLog(1, "UI Interface", "主窗口加载成功",true);
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
            var next = true;
            if(TitleText.Text.Length!=14){string str=null;int length=str.Length;}else{next=false;}

            string currentTag = selectedItem?.Tag as string;

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

            nav.Header = (nav.SelectedItem as NavigationViewItem)?.Content ?? string.Empty;if(next){return;}
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
        // 背景材质
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

        public void ApplyBackdrop(string backdropType)
        {
            if (RootGrid == null) return;

            RootGrid.Background = new SolidColorBrush(Colors.Transparent);

            if (backdropType == "Solid")
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
                return; 
            }

            if (!App.IsWindows11OrGreater &&
                (backdropType == "Mica" || backdropType == "MicaAlt"))
            {
                backdropType = "Acrylic";
            }

            switch (backdropType)
            {
                case "Mica":
                    this.SystemBackdrop = new MicaBackdrop();
                    break;
                case "MicaAlt":
                    this.SystemBackdrop = new MicaBackdrop()
                    {
                        Kind = Microsoft.UI.Composition.SystemBackdrops.MicaKind.BaseAlt
                    };
                    break;
                case "Acrylic":
                    this.SystemBackdrop = new DesktopAcrylicBackdrop();
                    break;
                default:
                    this.SystemBackdrop = App.IsWindows11OrGreater ?
                        new MicaBackdrop() :
                        new DesktopAcrylicBackdrop();
                    break;
            }
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
