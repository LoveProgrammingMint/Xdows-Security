using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using System;
using System.Diagnostics;
using Windows.ApplicationModel.Resources;
using Windows.Globalization;
using Windows.Storage;

namespace Xdows_Security
{
    public sealed partial class SettingsPage : Page
    {
        private readonly ResourceLoader _resourceLoader = ResourceLoader.GetForViewIndependentUse();

        public SettingsPage()
        {
            this.InitializeComponent();
            LoadLanguageSetting();
            LoadThemeSetting();
            LoadBackdropSetting();
            LoadScanSetting();
            Settings_About_Version.Text = _resourceLoader.GetString("APP_Version");
            if (App.GetCloudApiKey() == string.Empty) {
                CloudScanToggle.IsOn = false;
                CloudScanToggle.IsEnabled = false;
            }
        }
        private void RunProtection(object sender, RoutedEventArgs e)
        {
            var Toggle = sender as ToggleSwitch;

            if (Toggle?.IsOn == true)
            {
                int RunID = Toggle.Tag switch
                {
                    "Progress" => 0,
                    "Boot" => 1,
                    "Register" => 2,
                    _ => 0,
                };
                if (!Protection.Run(RunID)) {
                    Toggle.IsOn = !Toggle.IsOn;
                }
            }
            else
            {

            }
        }
        private void ScanProgressToggle_Toggled(object sender, RoutedEventArgs e)
        {
            var settings = ApplicationData.Current.LocalSettings;
            settings.Values["ShowScanProgress"] = ScanProgressToggle.IsOn;
        }
        private void DeepScanToggle_Toggled(object sender, RoutedEventArgs e)
        {
            var settings = ApplicationData.Current.LocalSettings;
            settings.Values["DeepScan"] = DeepScanToggle.IsOn;
        }
        private void ExtraDataToggle_Toggled(object sender, RoutedEventArgs e)
        {
            var settings = ApplicationData.Current.LocalSettings;
            settings.Values["ExtraData"] = ExtraDataToggle.IsOn;
        }
        private void SouXiaoScanToggle_Toggled(object sender, RoutedEventArgs e)
        {
            var settings = ApplicationData.Current.LocalSettings;
            settings.Values["SouXiaoScan"] = SouXiaoScanToggle.IsOn;
        }
        private void LocalScanToggle_Toggled(object sender, RoutedEventArgs e)
        {
            var settings = ApplicationData.Current.LocalSettings;
            settings.Values["LocalScan"] = LocalScanToggle.IsOn;
        }
        private void CloudScanToggle_Toggled(object sender, RoutedEventArgs e)
        {
            var settings = ApplicationData.Current.LocalSettings;
            settings.Values["CloudScan"] = CloudScanToggle.IsOn;
        }
        private void LoadScanSetting()
        {
            var settings = ApplicationData.Current.LocalSettings;
            if (settings.Values.TryGetValue("ShowScanProgress", out object? value))
            {
                bool showScanProgress = value is bool && (bool)value;
                ScanProgressToggle.IsOn = showScanProgress;
            }
            if (settings.Values.TryGetValue("DeepScan", out value))
            {
                bool DeepScan = value is bool && (bool)value;
                DeepScanToggle.IsOn = DeepScan;
            }
            if (settings.Values.TryGetValue("ExtraData", out value))
            {
                bool ExtraData = value is bool && (bool)value;
                ExtraDataToggle.IsOn = ExtraData;
            }
            if (settings.Values.TryGetValue("LocalScan", out value))
            {
                bool LocalScan = value is bool && (bool)value;
                LocalScanToggle.IsOn = LocalScan;
            }
            if (settings.Values.TryGetValue("CloudScan", out value))
            {
                bool CloudScan = value is bool && (bool)value;
                CloudScanToggle.IsOn = CloudScan;
            }
            if (settings.Values.TryGetValue("SouXiaoScan", out value))
            {
                bool SouXiaoScan = value is bool && (bool)value;
                SouXiaoScanToggle.IsOn = SouXiaoScan;
            }
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
                XamlRoot = this.XamlRoot,
                PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
            };

            var result = await dialog.ShowAsync();
            if (result == ContentDialogResult.Primary)
            {
                App.RestartApplication();
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
            if (ThemeComboBox.SelectedIndex == -1) return;

            ElementTheme selectedTheme = ElementTheme.Default;
            switch (ThemeComboBox.SelectedIndex)
            {
                case 0: selectedTheme = ElementTheme.Default; break;
                case 1: selectedTheme = ElementTheme.Light; break;
                case 2: selectedTheme = ElementTheme.Dark; break;
            }

            var settings = ApplicationData.Current.LocalSettings;
            settings.Values["AppTheme"] = selectedTheme.ToString();

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
            BackdropComboBox.SelectionChanged -= BackdropComboBox_SelectionChanged;

            var settings = ApplicationData.Current.LocalSettings;
            var savedBackdrop = settings.Values["AppBackdrop"] as string;

            MicaOption.IsEnabled = App.CheckWindowsVersion();
            MicaAltOption.IsEnabled = App.CheckWindowsVersion();

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
                BackdropComboBox.SelectedIndex = App.CheckWindowsVersion() ? 1 : 3;
            }

            BackdropComboBox.SelectionChanged += BackdropComboBox_SelectionChanged;
        }

        private void BackdropComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (BackdropComboBox.SelectedItem is ComboBoxItem selected)
            {
                string backdropType = selected.Tag as string ?? ElementTheme.Default.ToString();
                var settings = ApplicationData.Current.LocalSettings;
                settings.Values["AppBackdrop"] = backdropType;

                // Ó¦ÓÃÐÂ±³¾°
                if (App.MainWindow != null)
                {
                    App.MainWindow.ApplyBackdrop(backdropType);
                }
            }
        }
    }
}