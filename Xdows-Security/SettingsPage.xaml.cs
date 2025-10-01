using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.Windows.BadgeNotifications;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Xml.Schema;
using Windows.ApplicationModel.Resources;
using Windows.Globalization;
using Windows.Storage;
using Xdows.Protection;

namespace Xdows_Security
{
    public sealed partial class SettingsPage : Page
    {
        private readonly ResourceLoader _resourceLoader = ResourceLoader.GetForViewIndependentUse();
        private bool IsInitialize = true;
        public SettingsPage()
        {
            this.InitializeComponent();
            LoadLanguageSetting();
            LoadThemeSetting();
            LoadBackdropSetting();
            LoadScanSetting();
            Settings_About_Version.Text = _resourceLoader.GetString("APP_Version");
            if (App.GetCzkCloudApiKey() == string.Empty)
            {
                CzkCloudScanToggle.IsOn = false;
                CzkCloudScanToggle.IsEnabled = false;
            }

            //if (!File.Exists(AppDomain.CurrentDomain.BaseDirectory + "model.onnx")) {
            //    SouXiaoScanToggle.IsOn = false;
            //    SouXiaoScanToggle.IsEnabled = false;
            //    ProcessToggle.IsOn = false;
            //    ProcessToggle.IsEnabled = false;
            //    FilesToggle.IsOn = false;
            //    FilesToggle.IsEnabled = false;
            //}
            //if (!App.IsRunAsAdmin())
            //{
                RegistryToggle.IsEnabled = false;
                RegistryToggle.IsOn = false;
            //}
            IsInitialize = false;
        }
        private void RunProtectionWithToggle(ToggleSwitch toggle, int runId)
        {
            toggle.Toggled -= RunProtection;
            if (!Protection.Run(runId))
                toggle.IsOn = !toggle.IsOn;
            if (runId == 0)
                toggle.IsOn = ProcessProtection.IsEnabled();
            if (runId == 1)
                toggle.IsOn = FilesProtection.IsEnabled();
            if (runId == 4)
                toggle.IsOn = RegistryProtection.IsEnabled();
            toggle.Toggled += RunProtection;
        }

        private void RunProtection(object sender, RoutedEventArgs e)
        {
            if (sender is not ToggleSwitch toggle || IsInitialize) return;
            int runId = toggle.Tag switch
            {
                "Progress" => 0,
                "Files" => 1,
                "Registry" => 4,
                _ => 0
            };
            RunProtectionWithToggle(toggle, runId);
        }
        private void Toggled_SaveToggleData(object sender, RoutedEventArgs e)
        {
            if (sender is not ToggleSwitch toggle || IsInitialize) return;

            string key = toggle.Tag as string ?? toggle.Name;
            if (string.IsNullOrWhiteSpace(key)) return;

            var settings = ApplicationData.Current.LocalSettings;
            settings.Values[key] = toggle.IsOn;
        }
        private void LoadScanSetting()
        {
            var settings = ApplicationData.Current.LocalSettings;
            var toggles = new List<ToggleSwitch>
            {
                ScanProgressToggle,
                DeepScanToggle,
                ExtraDataToggle,
                LocalScanToggle,
                CzkCloudScanToggle,
                SouXiaoScanToggle,
                CloudScanToggle
            };

            foreach (var setting in toggles)
            {
                if (setting == null) continue;

                if (setting.Tag is string key && !string.IsNullOrWhiteSpace(key))
                {
                    if (settings.Values.TryGetValue(key, out object? toggleValue))
                    {
                        setting.IsOn = toggleValue is bool boolValue && boolValue;
                    }
                }
            }
            if (settings.Values.TryGetValue("AppBackdropOpacity", out object? opacityValue))
            {
                Appearance_Backdrop_Opacity.Value = (double)opacityValue;
            }
            else
            {
                Appearance_Backdrop_Opacity.Value = 100;
            }
            ProcessToggle.IsOn = ProcessProtection.IsEnabled();
            FilesToggle.IsOn = FilesProtection.IsEnabled();
            RegistryToggle.IsOn = RegistryProtection.IsEnabled();
        }
        private void LoadLanguageSetting()
        {
            var settings = ApplicationData.Current.LocalSettings;
            var savedLanguage = settings.Values["AppLanguage"] as string ?? "zh-HANS";

            foreach (ComboBoxItem item in LanguageComboBox.Items)
            {
                if (item.Tag as string == savedLanguage)
                {
                    LanguageComboBox.SelectedItem = item;
                    break;
                }
            }
        }

        private void LanguageComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            if (LanguageComboBox.SelectedItem is ComboBoxItem selectedItem)
            {
                var newLanguage = selectedItem.Tag as string;
                var currentLanguage = ApplicationLanguages.PrimaryLanguageOverride;

                if (newLanguage != currentLanguage)
                {
                    var settings = ApplicationData.Current.LocalSettings;
                    settings.Values["AppLanguage"] = newLanguage;
                    ApplicationLanguages.PrimaryLanguageOverride = newLanguage;

                    ShowRestartMessage();
                }
            }
        }

        private async void ShowRestartMessage()
        {
            if (this.XamlRoot == null) return;
            ContentDialog dialog = new ContentDialog
            {
                Title = _resourceLoader.GetString("Restart_Title"),
                Content = _resourceLoader.GetString("Restart_Message"),
                PrimaryButtonText = _resourceLoader.GetString("Button_Yes"),
                SecondaryButtonText = _resourceLoader.GetString("Button_No"),
                RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme,
                XamlRoot = this.XamlRoot,
                PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
            };
            var result = await dialog.ShowAsync();
            if (result == ContentDialogResult.Primary)
            {
                App.RestartApplication();
            }
            else
            {
                BadgeNotificationManager.Current.SetBadgeAsGlyph(BadgeNotificationGlyph.Activity);
            }
        }

        private void UpdateButtonClick(object sender, RoutedEventArgs e)
        {
            UpdateTeachingTip.ActionButtonContent = _resourceLoader.GetString("Button_Confirm");
            UpdateTeachingTip.IsOpen = !UpdateTeachingTip.IsOpen;
        }

        private void UpdateTeachingTipClose(TeachingTip sender, object args)
        {
            sender.IsOpen = false;
        }
        private void LoadThemeSetting()
        {
            var settings = ApplicationData.Current.LocalSettings;
            if (settings.Values.TryGetValue("AppTheme", out object? theme))
            {
                string themeString = theme as string ?? ElementTheme.Default.ToString();
                if (Enum.TryParse(themeString, out ElementTheme themeValue))
                {
                    switch (themeValue)
                    {
                        case ElementTheme.Default:
                            ThemeComboBox.SelectedIndex = 0;
                            break;
                        case ElementTheme.Light:
                            ThemeComboBox.SelectedIndex = 1;
                            break;
                        case ElementTheme.Dark:
                            ThemeComboBox.SelectedIndex = 2;
                            break;
                    }
                }
            }
            else
            {
                ThemeComboBox.SelectedIndex = 0;
            }
        }


        private void ThemeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize || ThemeComboBox.SelectedIndex == -1) return;

            ElementTheme selectedTheme = ElementTheme.Default;
            switch (ThemeComboBox.SelectedIndex)
            {
                case 0: selectedTheme = ElementTheme.Default; break;
                case 1: selectedTheme = ElementTheme.Light; break;
                case 2: selectedTheme = ElementTheme.Dark; break;
            }

            var settings = ApplicationData.Current.LocalSettings;
            settings.Values["AppTheme"] = selectedTheme.ToString();
            if (App.MainWindow == null) return;
            if (App.MainWindow.Content is FrameworkElement rootElement)
            {
                rootElement.RequestedTheme = selectedTheme;
            }
            App.MainWindow.UpdateTheme(selectedTheme);

            var backdrop = settings.Values["AppBackdrop"] as string;
            if (backdrop == "Solid" && App.MainWindow != null)
            {
                App.MainWindow.ApplyBackdrop(backdrop);
            }
        }

        private void LoadBackdropSetting()
        {
            var settings = ApplicationData.Current.LocalSettings;
            var savedBackdrop = settings.Values["AppBackdrop"] as string;

            Appearance_Backdrop_Opacity.IsEnabled = !(savedBackdrop == "Solid" || savedBackdrop == "MicaAlt");
            MicaOption.IsEnabled = MicaController.IsSupported();
            MicaAltOption.IsEnabled = MicaController.IsSupported();

            bool found = false;

            foreach (ComboBoxItem item in BackdropComboBox.Items)
            {
                if (item.Tag as string == savedBackdrop)
                {
                    BackdropComboBox.SelectedItem = item;
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                BackdropComboBox.SelectedIndex = MicaController.IsSupported() ? 1 : 3;
            }
        }

        private void BackdropComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            if (BackdropComboBox.SelectedItem is ComboBoxItem selected)
            {
                try
                {
                    string backdropType = selected.Tag as string ?? ElementTheme.Default.ToString();
                    var settings = ApplicationData.Current.LocalSettings;
                    settings.Values["AppBackdrop"] = backdropType;

                    // Ó¦ÓÃÐÂ±³¾°
                    if (App.MainWindow != null)
                    {
                        App.MainWindow.ApplyBackdrop(backdropType);
                    }
                    Appearance_Backdrop_Opacity.IsEnabled = !(backdropType == "Solid");
                }
                catch { }
            }
        }

        private void OpacitySlider_ValueChanged(object sender, RangeBaseValueChangedEventArgs e)
        {
            if (IsInitialize || sender is not Slider slider) return;
            var settings = ApplicationData.Current.LocalSettings;
            settings.Values["AppBackdropOpacity"] = slider.Value;
            if (App.MainWindow == null) return;
            App.MainWindow.ApplyBackdrop(settings.Values["AppBackdrop"] as string ?? "Mica");
        }
    }
}