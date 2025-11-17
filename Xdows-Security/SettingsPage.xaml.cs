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
using Compatibility.Windows.Storage;
using WinUI3Localizer;
using Xdows.Protection;

namespace Xdows_Security
{
    public sealed partial class SettingsPage : Page
    {
        private bool IsInitialize = true;
        public SettingsPage()
        {
            this.InitializeComponent();
            LoadLanguageSetting();
            LoadThemeSetting();
            LoadBackdropSetting();
            LoadScanSetting();
            Settings_About_Name.Text = AppInfo.AppName;
            Settings_About_Version.Text = AppInfo.AppVersion;
            Settings_About_Feedback.NavigateUri = new Uri(AppInfo.AppFeedback);
            Settings_About_Website.NavigateUri = new Uri(AppInfo.AppWebsite);
            if (App.GetCzkCloudApiKey() == string.Empty)
            {
                CzkCloudScanToggle.IsOn = false;
                CzkCloudScanToggle.IsEnabled = false;
            }

            //if (!File.Exists(AppDomain.CurrentDomain.BaseDirectory + "model.onnx")) {
            //SouXiaoScanToggle.IsOn = false;
            //SouXiaoScanToggle.IsEnabled = false;
            //ProcessToggle.IsOn = false;
            //ProcessToggle.IsEnabled = false;
            //FilesToggle.IsOn = false;
            //FilesToggle.IsEnabled = false;
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
        private void Settings_Feedback_Click(object sender, RoutedEventArgs e)
        {
            if(App.MainWindow != null)
                App.MainWindow.GoToBugReportPage(SettingsPage_Other_Feedback.Header.ToString());
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
            if (toggle.IsOn && (key == "CzkCloudScan" || key == "CloudScan"))
            {
                var dialog = new ContentDialog
                {
                    Title = "免责声明",
                    Content = "当您启用此引擎后，" +
                    "使用该引擎进行扫描文件时会将文件数据或其信息发送对应云服务提供商服务器。" +
                    "用户应自觉遵守相关服务协议、条约或声明，不发送涉及相关法律和隐私文件。" +
                    "任何由此引擎引发的文件泄露等问题或损失均由云服务提供商承担，此软件开发者不承担任何责任。" +
                    "因不可抗力因素如服务器故障等问题而引发的数据丢失等文件或损失，此软件开发者同样不承担任何责任。" +
                    "\n本声明或云服务提供协议、条约或声明会因软件更新等多种因素进行修改、删除、补充其内容，当发生纠纷时，请以最新版本为准，" +
                    "本软件开发者具有对此声明进行修改、删除、补充而不经用户同意的权力，该声明最终解释权归本软件开发者所有。" +
                    "\n对于此软件的分支产生的问题，此软件的源开发者（Xdows Software）不承担任何责任。" +
                    "\n当您通过任何方式使用该引擎时则表示同意并接受该声明，如果您不接受请自行关闭此引擎或停止使用并删除该软件。",
                    PrimaryButtonText = "确定",
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme,
                    PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                }.ShowAsync();
            }
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

            foreach (var toggle in toggles)
            {
                if (toggle == null) continue;

                if (toggle.Tag is string key && !string.IsNullOrWhiteSpace(key) &&
                    settings.Values.TryGetValue(key, out object raw) && raw is bool isOn)
                {
                    toggle.IsOn = isOn;
                }
            }

            if (settings.Values.TryGetValue("AppBackdropOpacity", out object opacityRaw) &&
                opacityRaw is double opacity)
            {
                Appearance_Backdrop_Opacity.Value = opacity;
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

            if (!settings.Values.TryGetValue("AppLanguage", out object langRaw) ||
                langRaw is not string savedLanguage)
            {
                savedLanguage = "en-US";
            }

            foreach (ComboBoxItem item in LanguageComboBox.Items)
            {
                if (item.Tag as string == savedLanguage)
                {
                    LanguageComboBox.SelectedItem = item;
                    break;
                }
            }
        }
        private void LoadThemeSetting()
        {
            var settings = ApplicationData.Current.LocalSettings;

            if (!settings.Values.TryGetValue("AppTheme", out object themeRaw) ||
                themeRaw is not string themeString ||
                !Enum.TryParse(themeString, out ElementTheme themeValue))
            {
                themeValue = ElementTheme.Default;
            }

            ThemeComboBox.SelectedIndex = themeValue switch
            {
                ElementTheme.Light => 1,
                ElementTheme.Dark => 2,
                _ => 0
            };

            NavComboBox.SelectedIndex = 
                settings.Values.TryGetValue("AppNavTheme", out object raw) && raw is double d ?
                (int)d : 0;
        }
        private async void LanguageComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            if (LanguageComboBox.SelectedItem is ComboBoxItem selectedItem)
            {
                var newLanguage = selectedItem.Tag as string;
                var currentLanguage = Localizer.Get().GetCurrentLanguage();
                if (newLanguage == null) return;
                if (newLanguage != currentLanguage)
                {
                    ApplicationData.Current.LocalSettings.Values["AppLanguage"] = newLanguage;
                    await Localizer.Get().SetLanguage(newLanguage);
                }
            }
        }

        private void UpdateButtonClick(object sender, RoutedEventArgs e)
        {
            UpdateTeachingTip.ActionButtonContent = Localizer.Get().GetLocalizedString("Button_Confirm");
            UpdateTeachingTip.IsOpen = !UpdateTeachingTip.IsOpen;
        }

        private void UpdateTeachingTipClose(TeachingTip sender, object args)
        {
            sender.IsOpen = false;
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

            Appearance_Backdrop_Opacity.IsEnabled = !(savedBackdrop == "Solid");
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

                    // 应用新背景
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

        private void NavComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            try
            {
                int index = NavComboBox.SelectedIndex;
                var settings = ApplicationData.Current.LocalSettings;
                settings.Values["AppNavTheme"] = index;
                App.MainWindow?.UpdateNavTheme(index);
            }
            catch { }
        }
    }
}