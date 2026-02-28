// MainWindow backdrop and theme management (partial class)
using Compatibility.Windows.Storage;
using Microsoft.UI;
using Microsoft.UI.Composition;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using System;
using Windows.UI;
using Windows.UI.ViewManagement;

namespace Xdows_Security
{
    public sealed partial class MainWindow
    {
        private string _lastBackdrop = "";
        private double _lastOpacity = 100;
        private ISystemBackdropControllerWithTargets? _controller;
        private ICompositionSupportsSystemBackdrop? _target;
        private static readonly SystemBackdropConfiguration _config = new()
        {
            IsInputActive = true
        };

        private ImageBrush? _backgroundImageBrush;
        private string? _currentBackgroundImagePath;

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
                titleBar?.ButtonForegroundColor = selectedTheme switch
                {
                    ElementTheme.Dark => Windows.UI.Color.FromArgb(255, 255, 255, 255),
                    ElementTheme.Light => Windows.UI.Color.FromArgb(255, 0, 0, 0),
                    _ => GetSystemTheme() == 0
                        ? Windows.UI.Color.FromArgb(255, 0, 0, 0)
                        : Windows.UI.Color.FromArgb(255, 255, 255, 255)
                };
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

        private ElementTheme GetCurrentTheme()
        {
            if (RootGrid.RequestedTheme != ElementTheme.Default)
                return RootGrid.RequestedTheme;

            var settings = new UISettings();
            var systemBackground = settings.GetColorValue(UIColorType.Background);
            return IsLightColor(systemBackground) ? ElementTheme.Light : ElementTheme.Dark;
        }

        public void ApplyBackdrop(string backdropType, bool compulsory)
        {
            try
            {
                if (RootGrid == null) return;
                var settings = ApplicationData.Current.LocalSettings;
                double opacity = settings.Values["AppBackdropOpacity"] is double v ? v :
                                (settings.Values["AppBackdropOpacity"] is int i ? i : 100);
                if (!compulsory && _lastBackdrop == backdropType && _lastOpacity.Equals(opacity))
                    return;

                CleanupBackdropResources();
                _lastBackdrop = backdropType;
                _lastOpacity = opacity;

                if (backdropType == "Solid")
                {
                    this.SystemBackdrop = null;
                    if (ApplicationData.HasFile("background_image"))
                        UpdateBackgroundImage();

                    RootGrid.Background = GetCurrentTheme() == ElementTheme.Dark
                         ? new SolidColorBrush(Color.FromArgb(0xFF, 0x20, 0x20, 0x20))
                         : new SolidColorBrush(Colors.White);
                    return;
                }

                if (backdropType is "Mica" or "MicaAlt" && !MicaController.IsSupported())
                    backdropType = "Acrylic";

                RootGrid.Background = new SolidColorBrush(Colors.Transparent);

                _target = (ICompositionSupportsSystemBackdrop)(object)this;

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
                            LuminosityOpacity = (float)(opacity / 100 * 0.85),
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

                if (ApplicationData.HasFile("background_image"))
                    UpdateBackgroundImage();
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
                    _controller.RemoveSystemBackdropTarget(_target);

                _controller.Dispose();
                _controller = null;
            }
            _target = null;
        }

        public async System.Threading.Tasks.Task ApplyBackgroundImageAsync(string imagePath)
        {
            try
            {
                _currentBackgroundImagePath = imagePath;
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

                var settings = ApplicationData.Current.LocalSettings;
                var opacityValue = settings.Values["AppBackgroundImageOpacity"] as double? ?? 30.0;
                _backgroundImageBrush.Opacity = opacityValue / 100.0;

                var dq = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread();
                dq?.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () =>
                {
                    UpdateBackgroundImage();
                });
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
                var settings = ApplicationData.Current.LocalSettings;
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
    }
}