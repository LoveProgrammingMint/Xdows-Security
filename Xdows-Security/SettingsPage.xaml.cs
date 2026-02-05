using CommunityToolkit.WinUI.Controls;
using Compatibility.Windows.Storage;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.WindowsAPICodePack.Dialogs;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using TrustQuarantine;
using Windows.Security.Credentials.UI;
using WinUI3Localizer;

namespace Xdows_Security
{
    public sealed partial class SettingsPage : Page
    {
        private bool IsInitialize = true;

        public SettingsPage()
        {
            this.InitializeComponent();

            _ = InitializeAsync();
        }

        private async Task InitializeAsync()
        {
            this.DispatcherQueue.TryEnqueue(async () =>
            {
                try
                {
                    Settings_About_Name.Text = AppInfo.AppName;
                    Settings_About_Version.Text = AppInfo.AppVersion;
                    Settings_About_Feedback.NavigateUri = new Uri(AppInfo.AppFeedback);
                    Settings_About_Website.NavigateUri = new Uri(AppInfo.AppWebsite);

                    if (App.GetCzkCloudApiKey() == string.Empty)
                    {
                        CzkCloudScanToggle?.IsOn = false;
                        CzkCloudScanToggle?.IsEnabled = false;
                    }

                    if (!File.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AX_API", "AX_API.exe")))
                    {
                        JiSuSafeAXToggle?.IsOn = false;
                        JiSuSafeAXToggle?.IsEnabled = false;
                    }

                    if (!App.IsRunAsAdmin())
                    {
                        RegistryToggle?.IsEnabled = false;
                        RegistryToggle?.IsOn = false;
                    }

                    await Task.WhenAll(
                        LoadScanSettingAsync,
                        LoadLanguageSettingAsync,
                        LoadThemeSettingAsync,
                        LoadBackdropSettingAsync,
                        LoadBackgroundImageSettingAsync
                    );
                }
                catch { }
                finally
                {
                    IsInitialize = false;
                }
            });
        }
        private Task LoadScanSettingAsync
        {
            get
            {
                var tcs = new TaskCompletionSource<object?>();
                this.DispatcherQueue.TryEnqueue(() =>
                {
                    try
                    {
                        LoadScanSetting();
                        tcs.SetResult(null);
                    }
                    catch (Exception ex)
                    {
                        tcs.SetException(ex);
                    }
                });
                return tcs.Task;
            }
        }

        private Task LoadLanguageSettingAsync
        {
            get
            {
                var tcs = new TaskCompletionSource<object?>();
                this.DispatcherQueue.TryEnqueue(() =>
                {
                    try
                    {
                        LoadLanguageSetting();
                        tcs.SetResult(null);
                    }
                    catch (Exception ex)
                    {
                        tcs.SetException(ex);
                    }
                });
                return tcs.Task;
            }
        }

        private Task LoadThemeSettingAsync
        {
            get
            {
                var tcs = new TaskCompletionSource<object?>();
                this.DispatcherQueue.TryEnqueue(() =>
                {
                    try
                    {
                        LoadThemeSetting();
                        tcs.SetResult(null);
                    }
                    catch (Exception ex)
                    {
                        tcs.SetException(ex);
                    }
                });
                return tcs.Task;
            }
        }

        private Task LoadBackdropSettingAsync
        {
            get
            {
                var tcs = new TaskCompletionSource<object?>();
                this.DispatcherQueue.TryEnqueue(() =>
                {
                    try
                    {
                        LoadBackdropSetting();
                        tcs.SetResult(null);
                    }
                    catch (Exception ex)
                    {
                        tcs.SetException(ex);
                    }
                });
                return tcs.Task;
            }
        }

        private Task LoadBackgroundImageSettingAsync
        {
            get
            {
                var tcs = new TaskCompletionSource<object?>();
                this.DispatcherQueue.TryEnqueue(() =>
                {
                    try
                    {
                        LoadBackgroundImageSetting();
                        tcs.SetResult(null);
                    }
                    catch (Exception ex)
                    {
                        tcs.SetException(ex);
                    }
                });
                return tcs.Task;
            }
        }

        private void RunProtectionWithToggle(ToggleSwitch toggle, int runId)
        {
            toggle.Toggled -= RunProtection;
            if (!ProtectionStatus.Run(runId))
                toggle.IsOn = !toggle.IsOn;
            toggle.IsOn = ProtectionStatus.IsRun(runId);
            toggle.Toggled += RunProtection;
        }
        private void Settings_Feedback_Click(object sender, RoutedEventArgs e)
        {
            App.MainWindow?.GoToBugReportPage(SettingsPage_Other_Feedback.Header.ToString());
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
                _ = new ContentDialog
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
                 TrayVisibleToggle,
                 DisabledVerifyToggle
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

            ProcessToggle.IsOn = ProtectionStatus.IsRun(0);
            FilesToggle.IsOn = ProtectionStatus.IsRun(1);
            RegistryToggle.IsOn = ProtectionStatus.IsRun(4);

            // Load scan index mode setting (default Parallel) without direct XAML field access
            try
            {
                var mode = settings.Values.TryGetValue("ScanIndexMode", out object raw) && raw is string s ? s : "Parallel";
                var combo = this.FindName("ScanIndexModeComboBox") as ComboBox;
                if (combo != null)
                {
                    foreach (var obj in combo.Items)
                    {
                        if (obj is ComboBoxItem item && (item.Tag as string) == mode)
                        {
                            combo.SelectedItem = item;
                            break;
                        }
                    }
                    // If Parallel mode, disable ScanProgress toggle
                    try
                    {
                        var toggle = this.FindName("ScanProgressToggle") as ToggleSwitch;
                        if (toggle != null)
                        {
                            if (mode == "Parallel")
                            {
                                toggle.IsOn = false;
                                toggle.IsEnabled = false;
                            }
                            else
                            {
                                toggle.IsEnabled = true;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private void ScanIndexModeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            if (sender is ComboBox combo && combo.SelectedItem is ComboBoxItem item && item.Tag is string tag)
            {
                var settings = ApplicationData.Current.LocalSettings;
                settings.Values["ScanIndexMode"] = tag;
                // If Parallel mode selected, disable ScanProgress toggle in UI and set setting false
                try
                {
                    var toggle = this.FindName("ScanProgressToggle") as ToggleSwitch;
                    if (toggle != null)
                    {
                        if (tag == "Parallel")
                        {
                            toggle.IsOn = false;
                            toggle.IsEnabled = false;
                            settings.Values["ShowScanProgress"] = false;
                        }
                        else
                        {
                            toggle.IsEnabled = true;
                        }
                    }
                }
                catch { }
            }
        }

        private async void LoadLanguageSetting()
        {
            var settings = ApplicationData.Current.LocalSettings;

            if (!settings.Values.TryGetValue("AppLanguage", out object langRaw) ||
                langRaw is not string savedLanguage)
            {
                savedLanguage = "en-US";
            }

            foreach (ComboBoxItem item in LanguageComboBox.Items.Cast<ComboBoxItem>())
            {
                if (item.Tag as string == savedLanguage)
                {
                    LanguageComboBox.SelectedItem = item;
                    break;
                }
            }
        }
        private async void LoadThemeSetting()
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
                var currentLanguage = Localizer.Get().GetCurrentLanguage();
                if (selectedItem.Tag is not string newLanguage) return;
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
                var box = new CommunityToolkit.WinUI.UI.Controls.MarkdownTextBlock
                {
                    Text = update.Content,
                    IsTextSelectionEnabled = true,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(12),
                    Background = null
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
            catch
            {
                try
                {
                    UpdateTeachingTip.ActionButtonContent = Localizer.Get().GetLocalizedString("Button_Confirm");
                    UpdateTeachingTip.IsOpen = !UpdateTeachingTip.IsOpen;
                }
                catch { }
            }
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
            MainWindow.UpdateTheme(selectedTheme);//加盖史山ing...
        }

        public void UpdateThemeforLoad(ElementTheme Theme) => MainWindow.UpdateTheme(Theme); //细节：语法糖

        private async void LoadBackdropSetting()
        {
            var settings = ApplicationData.Current.LocalSettings;

            var savedBackdrop = settings.Values["AppBackdrop"] as string;

            Appearance_Backdrop_Opacity.IsEnabled = !(savedBackdrop == "Solid");
            MicaOption.IsEnabled = MicaController.IsSupported();
            MicaAltOption.IsEnabled = MicaController.IsSupported();

            bool found = false;

            foreach (ComboBoxItem item in BackdropComboBox.Items.Cast<ComboBoxItem>())
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

        private async void LoadBackgroundImageSetting()
        {
            try
            {
                var settings = ApplicationData.Current.LocalSettings;
                var backdropType = settings.Values["AppBackdrop"] as string ?? "Solid";
                var opacityValue = settings.Values["AppBackgroundImageOpacity"] as double? ?? 30.0;
                BackgroundImageOpacitySlider.Value = opacityValue;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"加载背景图片设置失败: {ex.Message}");
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
                    App.MainWindow?.ApplyBackdrop(backdropType, false);
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
            App.MainWindow.ApplyBackdrop(settings.Values["AppBackdrop"] as string ?? "Mica", false);
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
        private async void Quarantine_ViewButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new QuarantineDialog
                {
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                };

                await dialog.ShowAsync();
            }
            catch { }
        }
        private async void Quarantine_ClearButton_Click(object sender, RoutedEventArgs e)
        {
            _ = QuarantineManager.ClearQuarantine();
        }
        private async void Trust_ViewButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new TrustDialog
                {
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                };

                _ = dialog.ShowAsync();
            }
            catch { }
        }
        private async void Trust_AddButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                using var dlg = new CommonOpenFileDialog
                {
                    Title = Localizer.Get().GetLocalizedString("TrustDialog_SelectFile_Title"),
                    IsFolderPicker = false,
                    EnsurePathExists = true,
                };
                if (dlg.ShowDialog() == CommonFileDialogResult.Ok)
                {
                    bool success = await TrustManager.AddToTrust(dlg.FileName);
                }
            }
            catch { }
        }

        private void TrayVisibleToggle_Toggled(object sender, RoutedEventArgs e)
        {
            Toggled_SaveToggleData(sender, e);
            App.MainWindow?.manager?.IsVisibleInTray = TrayVisibleToggle.IsEnabled;
        }

        private void SettingsSearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
        {
            if (args.Reason == AutoSuggestionBoxTextChangeReason.UserInput)
            {
                string searchText = sender.Text.ToLowerInvariant();

                if (string.IsNullOrWhiteSpace(searchText))
                {
                    ShowAllSettingsItems();
                    return;
                }

                FilterSettingsItems(searchText);
            }
        }

        private void ShowAllSettingsItems()
        {
            var scrollViewer = this.Content as ScrollViewer;
            if (scrollViewer == null) return;

            var stackPanel = scrollViewer.Content as StackPanel;
            if (stackPanel == null) return;

            foreach (var child in stackPanel.Children)
            {
                if (child is AutoSuggestBox) continue;

                if (child is FrameworkElement element)
                {
                    element.Visibility = Visibility.Visible;

                    if (element is SettingsExpander expander)
                    {
                        foreach (var expanderChild in expander.Items)
                        {
                            if (expanderChild is SettingsCard card)
                            {
                                card.Visibility = Visibility.Visible;
                            }
                        }
                    }
                }
            }
        }
        private void FilterSettingsItems(string searchText)
        {
            var scrollViewer = this.Content as ScrollViewer;
            if (scrollViewer == null) return;

            var stackPanel = scrollViewer.Content as StackPanel;
            if (stackPanel == null) return;

            foreach (var child in stackPanel.Children)
            {
                if (child is AutoSuggestBox) continue;

                if (child is FrameworkElement element)
                {
                    element.Visibility = Visibility.Collapsed;

                    if (element is SettingsExpander expander)
                    {
                        foreach (var expanderChild in expander.Items)
                        {
                            if (expanderChild is SettingsCard card)
                            {
                                card.Visibility = Visibility.Collapsed;
                            }
                        }
                    }
                }
            }

            bool currentHeaderMatched = false;

            for (int i = 0; i < stackPanel.Children.Count; i++)
            {
                var child = stackPanel.Children[i];

                if (child is AutoSuggestBox) continue;

                if (child is FrameworkElement element)
                {
                    if (element is TextBlock textBlock)
                    {
                        currentHeaderMatched = IsSettingsItemMatched(textBlock, searchText);

                        if (currentHeaderMatched)
                        {
                            textBlock.Visibility = Visibility.Visible;
                        }
                    }
                    else if (element is SettingsCard || element is SettingsExpander)
                    {
                        bool shouldShow = false;

                        if (IsSettingsItemMatched(element, searchText))
                        {
                            shouldShow = true;
                        }

                        if (!shouldShow && currentHeaderMatched)
                        {
                            shouldShow = true;
                        }

                        if (element is SettingsExpander expander)
                        {
                            foreach (var expanderChild in expander.Items)
                            {
                                if (expanderChild is SettingsCard card)
                                {
                                    if (IsSettingsItemMatched(card, searchText) || currentHeaderMatched)
                                    {
                                        shouldShow = true;
                                        card.Visibility = Visibility.Visible;
                                    }
                                }
                            }
                        }

                        if (shouldShow)
                        {
                            element.Visibility = Visibility.Visible;
                        }
                    }
                }
            }
        }
        private static bool IsSettingsItemMatched(FrameworkElement item, string searchText)
        {
            string itemText = GetSettingsItemText(item);

            if (string.IsNullOrEmpty(itemText))
                return false;

            return itemText.Contains(searchText, StringComparison.InvariantCultureIgnoreCase);
        }
        private static string GetSettingsItemText(FrameworkElement item)
        {
            if (item is TextBlock textBlock)
            {
                return textBlock.Text;
            }
            else if (item is SettingsCard card)
            {
                return card.Header?.ToString() ?? string.Empty;
            }
            else if (item is SettingsExpander expander)
            {
                return expander.Header?.ToString() ?? string.Empty;
            }

            return string.Empty;
        }
        private bool DisabledVerifyToggleVerify = true;
        private async void DisabledVerifyToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (!DisabledVerifyToggleVerify || IsInitialize)
            {
                return;
            }
            if (DisabledVerifyToggle.IsOn)
            {
                DisabledVerifyToggleVerify = false;
                DisabledVerifyToggle.IsOn = false;
                var result = await UserConsentVerifier.RequestVerificationAsync(string.Empty);
                if (result == UserConsentVerificationResult.DeviceNotPresent ||
                result == UserConsentVerificationResult.DisabledByPolicy ||
                result == UserConsentVerificationResult.NotConfiguredForUser ||
                result == UserConsentVerificationResult.Verified)
                {
                    DisabledVerifyToggle.IsOn = true;
                    Toggled_SaveToggleData(sender, e);
                }
                DisabledVerifyToggleVerify = true;
            }
            else
            {
                Toggled_SaveToggleData(sender, e);
            }
        }
        private async void SelectBackgroundImageButton_Click(object sender, RoutedEventArgs e)
        {
            using var dlg = new Microsoft.WindowsAPICodePack.Dialogs.CommonOpenFileDialog
            {
                Title = Localizer.Get().GetLocalizedString("SettingsPage_BackgroundImage_SelectDialog_Title"),
                Filters =
                {
                    new Microsoft.WindowsAPICodePack.Dialogs.CommonFileDialogFilter(Localizer.Get().GetLocalizedString("SettingsPage_BackgroundImage_ImageFiles"), "*.jpg;*.jpeg;*.png;*.bmp;*.gif"),
                    new Microsoft.WindowsAPICodePack.Dialogs.CommonFileDialogFilter(Localizer.Get().GetLocalizedString("SettingsPage_BackgroundImage_AllFiles"), "*.*")
                },
                EnsureFileExists = true
            };

            if (dlg.ShowDialog() == Microsoft.WindowsAPICodePack.Dialogs.CommonFileDialogResult.Ok)
            {
                try
                {
                    string imagePath = dlg.FileName;
                    string key = "background_image";
                    await ApplicationData.WriteFileAsync(key, imagePath);

                    // 应用背景图片
                    App.MainWindow?.ApplyBackgroundImageAsync(imagePath);
                }
                catch (Exception ex)
                {
                    var errorDialog = new ContentDialog
                    {
                        Title = Localizer.Get().GetLocalizedString("SettingsPage_BackgroundImage_Error_Title"),
                        Content = string.Format(Localizer.Get().GetLocalizedString("SettingsPage_BackgroundImage_SelectError_Content"), ex.Message),
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        XamlRoot = this.XamlRoot
                    };
                    await errorDialog.ShowAsync();
                }
            }
        }

        private async void ClearBackgroundImageButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (ApplicationData.HasFile("background_image"))
                {
                    await ApplicationData.DeleteFileAsync("background_image");
                    App.MainWindow?.ClearBackgroundImage();
                }
            }
            catch (Exception ex)
            {
                var errorDialog = new ContentDialog
                {
                    Title = Localizer.Get().GetLocalizedString("SettingsPage_BackgroundImage_Error_Title"),
                    Content = string.Format(Localizer.Get().GetLocalizedString("SettingsPage_BackgroundImage_ClearError_Content"), ex.Message),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot
                };
                await errorDialog.ShowAsync();
            }
        }

        private async void OpenConfigLocationButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var path = ApplicationData.LocalFolder.Path;
                await Windows.System.Launcher.LaunchFolderPathAsync(path);
            }
            catch (Exception ex)
            {
                var errorDialog = new ContentDialog
                {
                    Title = Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Location_OpenFailed_Title"),
                    Content = string.Format(Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Location_OpenFailed_Content"), ex.Message),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot
                };
                await errorDialog.ShowAsync();
            }
        }

        private async void ResetConfigButton_Click(object sender, RoutedEventArgs e)
        {
            var confirmDialog = new ContentDialog
            {
                Title = Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Reset_Confirm_Title"),
                Content = Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Reset_Confirm_Content"),
                PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                XamlRoot = this.XamlRoot,
                PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
            };

            if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary)
            {
                try
                {
                    var path = ApplicationData.LocalFolder.Path;
                    if (Directory.Exists(path))
                    {
                        Directory.Delete(path, true);
                    }
                }
                catch (Exception ex)
                {
                    var errorDialog = new ContentDialog
                    {
                        Title = Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Reset_DeleteFailed_Title"),
                        Content = string.Format(Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Reset_DeleteFailed_Content"), ex.Message),
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        XamlRoot = this.XamlRoot
                    };
                    await errorDialog.ShowAsync();
                    return;
                }

                try
                {
                    var current = Process.GetCurrentProcess().MainModule?.FileName;
                    if (!string.IsNullOrEmpty(current))
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = current,
                            UseShellExecute = true
                        });
                    }
                }
                catch { }

                App.MainWindow?.Close();
                Environment.Exit(0);
            }
        }

        private void BackgroundImageOpacitySlider_ValueChanged(object sender, RoutedEventArgs e)
        {
            if (IsInitialize || sender is not Slider slider) return;

            // 保存透明度设置
            var settings = ApplicationData.Current.LocalSettings;
            settings.Values["AppBackgroundImageOpacity"] = slider.Value;

            // 应用新的透明度
            App.MainWindow?.UpdateBackgroundImageOpacity(slider.Value / 100.0);
        }
    }
}