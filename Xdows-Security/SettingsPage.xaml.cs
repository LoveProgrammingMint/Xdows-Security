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
using Xdows.UI.Dialogs;
using System.Threading.Tasks;

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

            // 检查AX_API.exe是否存在
            string axApiPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AX_API", "AX_API.exe");
            if (!File.Exists(axApiPath))
            {
                JiSuSafeAXToggle.IsOn = false;
                JiSuSafeAXToggle.IsEnabled = false;
            }

            //if (!File.Exists(AppDomain.CurrentDomain.BaseDirectory + "model.onnx")) {
            //SouXiaoScanToggle.IsOn = false;
            //SouXiaoScanToggle.IsEnabled = false;
            //ProcessToggle.IsOn = false;
            //ProcessToggle.IsEnabled = false;
            //FilesToggle.IsOn = false;
            //FilesToggle.IsEnabled = false;
            //}
            if (!App.IsRunAsAdmin())
            {
                RegistryToggle.IsEnabled = false;
                RegistryToggle.IsOn = false;
            }
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
        private async void Toggled_SaveToggleData(object sender, RoutedEventArgs e)
        {
            if (sender is not ToggleSwitch toggle || IsInitialize) return;

            string key = toggle.Tag as string ?? toggle.Name;
            if (string.IsNullOrWhiteSpace(key)) return;
            if (toggle.IsOn && (key == "CzkCloudScan" || key == "CloudScan"))
            {
                var dialog = new ContentDialog
                {
                    Title = Localizer.Get().GetLocalizedString("SettingsPage_Scan_Cloud_Disclaimer_Title"),
                    Content = Localizer.Get().GetLocalizedString("SettingsPage_Scan_Cloud_Disclaimer_Text"),
                    PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
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
                 JiSuSafeAXToggle,
                 SouXiaoScanToggle,
                 CloudScanToggle,
                 TrayVisibleToggle
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

        private async void UpdateButtonClick(object sender, RoutedEventArgs e)
        {
            try
            {
                UpdateButton.IsEnabled = false;
                UpdateProgressRing.IsActive = true;
                UpdateProgressRing.Visibility = Visibility.Visible;

                var update = await Updater.CheckUpdateAsync();
                if (update == null)
                {
                    UpdateButton.IsEnabled = true;
                    UpdateProgressRing.IsActive = false;
                    UpdateProgressRing.Visibility = Visibility.Collapsed;
                    UpdateTeachingTip.ActionButtonContent = Localizer.Get().GetLocalizedString("Button_Confirm");
                    UpdateTeachingTip.IsOpen = !UpdateTeachingTip.IsOpen;
                    return;
                }
                var box = new TextBlock
                {
                    Text = update.Content,
                    IsTextSelectionEnabled = true,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(12)
                };
                var scrollViewer = new ScrollViewer
                {
                    Content = box,
                    MaxHeight = 320,
                    HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto
                };

                var dialog = new ContentDialog
                {
                    Title = update.Title,
                    Content = scrollViewer,
                    PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Download"),
                    SecondaryButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                };

                var result = await dialog.ShowAsync();
                if (result == ContentDialogResult.Primary)
                {
                    await Windows.System.Launcher.LaunchUriAsync(new Uri(update.DownloadUrl));
                }
            }
            catch { }
            finally
            {
                UpdateButton.IsEnabled = true;
                UpdateProgressRing.IsActive = false;
                UpdateProgressRing.Visibility = Visibility.Collapsed;
            }
        }

        private void UpdateTeachingTipClose(TeachingTip sender, object args)
        {
            sender.IsOpen = false;
        }
        private void ThemeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize || ThemeComboBox.SelectedIndex == -1) return;

            ElementTheme selectedTheme = ThemeComboBox.SelectedIndex switch
            {
                0 => ElementTheme.Default,
                1 => ElementTheme.Light,
                2 => ElementTheme.Dark,
                _ => ElementTheme.Default
            };

            var settings = ApplicationData.Current.LocalSettings;
            settings.Values["AppTheme"] = selectedTheme.ToString();
            if (App.MainWindow == null) return;
            if (App.MainWindow.Content is FrameworkElement rootElement)
            {
                rootElement.RequestedTheme = selectedTheme;
            }
            App.MainWindow.UpdateTheme(selectedTheme);
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
                        App.MainWindow.ApplyBackdrop(backdropType,false);
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
            App.MainWindow.ApplyBackdrop(settings.Values["AppBackdrop"] as string ?? "Mica",false);
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

        /// <summary>
        /// 隔离区查看按钮点击事件
        /// </summary>
        private async void Quarantine_ViewButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new QuarantineDialog
                {
                    XamlRoot = this.XamlRoot
                };

                await dialog.ShowAsync();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"打开隔离区对话框失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 隔离区清空按钮点击事件
        /// </summary>
        private async void Quarantine_ClearButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                int count = QuarantineManager.GetQuarantineCount();
                
                if (count == 0)
                {
                    var emptyDialog = new ContentDialog
                    {
                        Title = "隔离区为空",
                        Content = "隔离区中没有文件需要清空。",
                        CloseButtonText = "确定",
                        XamlRoot = this.XamlRoot
                    };
                    await emptyDialog.ShowAsync();
                    return;
                }

                var confirmDialog = new ContentDialog
                {
                    Title = "确认清空",
                    Content = $"确定要永久删除隔离区中的所有 {count} 个文件吗？此操作不可撤销。",
                    PrimaryButtonText = "清空所有",
                    CloseButtonText = "取消",
                    DefaultButton = ContentDialogButton.Close,
                    XamlRoot = this.XamlRoot
                };

                if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary)
                {
                    bool success = QuarantineManager.ClearQuarantine();
                    
                    if (success)
                    {
                        var successDialog = new ContentDialog
                        {
                            Title = "隔离区已清空",
                            Content = "所有文件已从隔离区永久删除。",
                            CloseButtonText = "确定",
                            XamlRoot = this.XamlRoot
                        };
                        await successDialog.ShowAsync();
                    }
                    else
                    {
                        var errorDialog = new ContentDialog
                        {
                            Title = "清空失败",
                            Content = "清空隔离区时发生错误，请重试。",
                            CloseButtonText = "确定",
                            XamlRoot = this.XamlRoot
                        };
                        await errorDialog.ShowAsync();
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"清空隔离区失败: {ex.Message}");
                
                var errorDialog = new ContentDialog
                {
                    Title = "清空失败",
                    Content = "清空隔离区时发生错误，请重试。",
                    CloseButtonText = "确定",
                    XamlRoot = this.XamlRoot
                };
                await errorDialog.ShowAsync();
            }
        }

        /// <summary>
        /// 信任区查看按钮点击事件
        /// </summary>
        private async void Trust_ViewButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new TrustDialog
                {
                    XamlRoot = this.XamlRoot
                };

                await dialog.ShowAsync();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"打开信任区对话框失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 信任区添加按钮点击事件
        /// </summary>
        private async void Trust_AddButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new AddTrustDialog
                {
                    XamlRoot = this.XamlRoot
                };

                await dialog.ShowAsync();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"打开添加信任项对话框失败: {ex.Message}");
            }
        }

        private void TrayVisibleToggle_Toggled(object sender, RoutedEventArgs e)
        {
            Toggled_SaveToggleData(sender, e);
            App.MainWindow?.manager?.IsVisibleInTray = TrayVisibleToggle.IsEnabled;
        }
    }
}