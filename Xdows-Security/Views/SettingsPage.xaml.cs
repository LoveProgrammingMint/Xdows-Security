using CommunityToolkit.WinUI.Controls;
using Compatibility.Windows.Storage;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.Windows.Storage.Pickers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using TrustQuarantine;
using Windows.Security.Credentials.UI;
using WinUI3Localizer;

namespace Xdows_Security.Views
{
    public sealed partial class SettingsPage : Page
    {
        private Boolean IsInitialize = true;

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

                    if (App.GetCzkCloudApiKey() == String.Empty)
                    {
                        CzkCloudScanToggle?.IsOn = false;
                        CzkCloudScanToggle?.IsEnabled = false;
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
                    WinUI3Localizer.Localizer.Get().LanguageChanged += (s, e) => UpdateAppText();
                    UpdateAppText();
                }
                catch { }
                finally
                {
                    IsInitialize = false;
                }
            });
        }
        private void UpdateAppText()
        {
            SettingsPage_Protection_Registry.Header += " (Beta)";
        }

        private Task LoadScanSettingAsync
        {
            get
            {
                return RunOnDispatcher(LoadScanSetting);
            }
        }

        private Task LoadLanguageSettingAsync
        {
            get
            {
                return RunOnDispatcher(LoadLanguageSetting);
            }
        }

        private Task LoadThemeSettingAsync
        {
            get
            {
                return RunOnDispatcher(LoadThemeSetting);
            }
        }

        private Task LoadBackdropSettingAsync
        {
            get
            {
                return RunOnDispatcher(LoadBackdropSetting);
            }
        }

        private Task LoadBackgroundImageSettingAsync
        {
            get
            {
                return RunOnDispatcher(LoadBackgroundImageSetting);
            }
        }

        private Task<object?> RunOnDispatcher(Action action)
        {
            TaskCompletionSource<Object?> tcs = new();
            this.DispatcherQueue.TryEnqueue(() =>
            {
                try
                {
                    action();
                    tcs.SetResult(null);
                }
                catch (Exception ex)
                {
                    tcs.SetException(ex);
                }
            });
            return tcs.Task;
        }

        private void RunProtectionWithToggle(ToggleSwitch toggle, Int32 runId)
        {
            toggle.Toggled -= RunProtection;
            if (!ProtectionStatus.Run(runId))
                toggle.IsOn = !toggle.IsOn;
            toggle.IsOn = ProtectionStatus.IsRun(runId);
            toggle.Toggled += RunProtection;
            if (runId == 0)
            {
                Process_CompatibilityMode.IsEnabled = !ProtectionStatus.IsRun(0);
            }
            if (runId == 1)
            {
                Files_CompatibilityMode.IsEnabled = !ProtectionStatus.IsRun(1);
            }
        }

        private void Settings_Feedback_Click(Object sender, RoutedEventArgs e)
        {
            App.MainWindow?.GoToBugReportPage(SettingsPage_Other_Feedback.Header.ToString());
        }

        private void RunProtection(Object sender, RoutedEventArgs e)
        {
            if (sender is not ToggleSwitch toggle || IsInitialize) return;
            String tag = toggle.Tag as String ?? String.Empty;
            Int32 runId = tag switch
            {
                "Progress" => 0,
                "Files" => 1,
                "Registry" => 4,
                _ => 0
            };
            RunProtectionWithToggle(toggle, runId);
        }

        private async void Toggled_SaveToggleData(Object sender, RoutedEventArgs e)
        {
            if (sender is not ToggleSwitch toggle || IsInitialize) return;

            String key = toggle.Tag as String ?? toggle.Name;
            if (String.IsNullOrWhiteSpace(key)) return;
            if (toggle.IsOn && (key == "CzkCloudScan" || key == "CloudScan"))
            {
                _ = new ContentDialog
                {
                    Title = Localizer.Get().GetLocalizedString("SettingsPage_Scan_Cloud_Disclaimer_Title"),
                    Content = Localizer.Get().GetLocalizedString("SettingsPage_Scan_Cloud_Disclaimer_Text"),
                    PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    DefaultButton = ContentDialogButton.Primary
                }.ShowAsync();
            }
            var settings = ApplicationData.Current.LocalSettings;
            settings.Values[key] = toggle.IsOn;
        }

        private void LoadScanSetting()
        {
            var settings = ApplicationData.Current.LocalSettings;

            List<ToggleSwitch> toggles =
            [
                ScanProgressToggle,
                DeepScanToggle,
                ExtraDataToggle,
                LocalScanToggle,
                CzkCloudScanToggle,
                SouXiaoScanToggle,
                CloudScanToggle,
                TrayVisibleToggle,
                DisabledVerifyToggle,
                Process_CompatibilityMode,
                Files_CompatibilityMode,
            ];

            foreach (ToggleSwitch toggle in toggles)
            {
                if (toggle == null) continue;

                String key = toggle.Tag as String ?? "";
                if (!String.IsNullOrWhiteSpace(key) && settings.Values.TryGetValue(key, out Object raw) && raw is Boolean isOn)
                {
                    toggle.IsOn = isOn;
                }
            }

            if (settings.Values.TryGetValue("AppBackdropOpacity", out Object opacityRaw) && opacityRaw is Double opacity)
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
                String mode = settings.Values.TryGetValue("ScanIndexMode", out Object raw) && raw is String s ? s : "Parallel";
                ComboBox combo = this.FindName("ScanIndexModeComboBox") as ComboBox ?? new();
                if (combo != null)
                {
                    foreach (Object obj in combo.Items)
                    {
                        if (obj is ComboBoxItem item && (item.Tag as String) == mode)
                        {
                            combo.SelectedItem = item;
                            break;
                        }
                    }
                    // If Parallel mode, disable ScanProgress toggle
                    try
                    {
                        ToggleSwitch toggle = this.FindName("ScanProgressToggle") as ToggleSwitch ?? new();
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

        private void ScanIndexModeComboBox_SelectionChanged(Object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            if (sender is ComboBox combo && combo.SelectedItem is ComboBoxItem item && item.Tag is String tag)
            {
                ApplicationDataContainer settings = ApplicationData.Current.LocalSettings;
                settings.Values["ScanIndexMode"] = tag;
                try
                {
                    ToggleSwitch toggle = this.FindName("ScanProgressToggle") as ToggleSwitch ?? new();
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
            ApplicationDataContainer settings = ApplicationData.Current.LocalSettings;
            if (!settings.Values.TryGetValue("AppLanguage", out Object langRaw) || langRaw is not String savedLanguage)
            {
                savedLanguage = "en-US";
            }

            foreach (ComboBoxItem item in LanguageComboBox.Items.Cast<ComboBoxItem>())
            {
                if (item.Tag as String == savedLanguage)
                {
                    LanguageComboBox.SelectedItem = item;
                    break;
                }
            }
        }

        private async void LoadThemeSetting()
        {
            ApplicationDataContainer settings = ApplicationData.Current.LocalSettings;
            ElementTheme themeValue = ElementTheme.Default;
            if (settings.Values.TryGetValue("AppTheme", out Object themeRaw) && themeRaw is String themeString && Enum.TryParse(themeString, out ElementTheme parsedTheme))
            {
                themeValue = parsedTheme;
            }

            ThemeComboBox.SelectedIndex = themeValue switch
            {
                ElementTheme.Light => 1,
                ElementTheme.Dark => 2,
                _ => 0
            };

            NavComboBox.SelectedIndex = settings.Values.TryGetValue("AppNavTheme", out Object raw) && raw is Double d ? (Int32)d : 0;

        }

        private async void LanguageComboBox_SelectionChanged(Object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            if (LanguageComboBox.SelectedItem is ComboBoxItem selectedItem)
            {
                String currentLanguage = Localizer.Get().GetCurrentLanguage();
                if (selectedItem.Tag is not String newLanguage) return;
                if (newLanguage != currentLanguage)
                {
                    ApplicationData.Current.LocalSettings.Values["AppLanguage"] = newLanguage;
                    await Localizer.Get().SetLanguage(newLanguage);
                }
            }
        }

        private async void UpdateButtonClick(Object sender, RoutedEventArgs e)
        {
            try
            {
                UpdateButton.IsEnabled = false;
                UpdateProgressRing.IsActive = true;
                UpdateProgressRing.Visibility = Visibility.Visible;

                UpdateInfo? update = await Updater.CheckUpdateAsync();
                if (update == null)
                {
                    UpdateButton.IsEnabled = true;
                    UpdateProgressRing.IsActive = false;
                    UpdateProgressRing.Visibility = Visibility.Collapsed;
                    UpdateTeachingTip.ActionButtonContent = Localizer.Get().GetLocalizedString("Button_Confirm");
                    UpdateTeachingTip.IsOpen = !UpdateTeachingTip.IsOpen;
                    return;
                }
                TextBlock box = new()
                {
                    Text = update.Content,
                    IsTextSelectionEnabled = true,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(12),
                };
                ScrollViewer scrollViewer = new()
                {
                    Content = box,
                    MaxHeight = 320,
                    HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto
                };

                ContentDialog dialog = new()
                {
                    Title = update.Title,
                    Content = scrollViewer,
                    PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Download"),
                    SecondaryButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    DefaultButton = ContentDialogButton.Primary
                };

                ContentDialogResult result = await dialog.ShowAsync();
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

#pragma warning disable CA1822
        private void UpdateTeachingTipClose(TeachingTip sender, Object args)
#pragma warning restore CA1822
        {
            sender.IsOpen = false;
        }

        private void ThemeComboBox_SelectionChanged(Object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize || ThemeComboBox.SelectedIndex == -1) return;

            ElementTheme selectedTheme = ThemeComboBox.SelectedIndex switch
            {
                0 => ElementTheme.Default,
                1 => ElementTheme.Light,
                2 => ElementTheme.Dark,
                _ => ElementTheme.Default
            };

            ApplicationDataContainer settings = ApplicationData.Current.LocalSettings;
            settings.Values["AppTheme"] = selectedTheme.ToString();
            if (App.MainWindow == null) return;
            if (App.MainWindow.Content is FrameworkElement rootElement)
            {
                rootElement.RequestedTheme = selectedTheme;
            }
            MainWindow.UpdateTheme(selectedTheme);
        }

        public static void UpdateThemeforLoad(ElementTheme Theme)
        {
            MainWindow.UpdateTheme(Theme);
        }

        private async void LoadBackdropSetting()
        {
            ApplicationDataContainer settings = ApplicationData.Current.LocalSettings;
            String savedBackdrop = settings.Values["AppBackdrop"] as String ?? "";

            Appearance_Backdrop_Opacity.IsEnabled = !(savedBackdrop == "Solid");
            MicaOption.IsEnabled = MicaController.IsSupported();
            MicaAltOption.IsEnabled = MicaController.IsSupported();

            Boolean found = false;
            foreach (ComboBoxItem item in BackdropComboBox.Items.Cast<ComboBoxItem>())
            {
                if (item.Tag as String == savedBackdrop)
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
                ApplicationDataContainer settings = ApplicationData.Current.LocalSettings;
                String backdropType = settings.Values["AppBackdrop"] as String ?? "Solid";
                Double opacityValue = settings.Values["AppBackgroundImageOpacity"] as Double? ?? 30.0;
                BackgroundImageOpacitySlider.Value = opacityValue;
            }
            catch { }
        }

        private void BackdropComboBox_SelectionChanged(Object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            if (BackdropComboBox.SelectedItem is ComboBoxItem selected)
            {
                try
                {
                    String backdropType = selected.Tag as String ?? ElementTheme.Default.ToString();
                    ApplicationDataContainer settings = ApplicationData.Current.LocalSettings;
                    settings.Values["AppBackdrop"] = backdropType;
                    App.MainWindow?.ApplyBackdrop(backdropType, false);
                    Appearance_Backdrop_Opacity.IsEnabled = !(backdropType == "Solid");
                }
                catch { }
            }
        }

        private void OpacitySlider_ValueChanged(Object sender, RangeBaseValueChangedEventArgs e)
        {
            if (IsInitialize || sender is not Slider slider) return;
            ApplicationDataContainer settings = ApplicationData.Current.LocalSettings;
            settings.Values["AppBackdropOpacity"] = slider.Value;
            if (App.MainWindow == null) return;
            App.MainWindow.ApplyBackdrop(settings.Values["AppBackdrop"] as String ?? "Mica", false);
        }

        private void NavComboBox_SelectionChanged(Object sender, SelectionChangedEventArgs e)
        {
            if (IsInitialize) return;
            try
            {
                Int32 index = NavComboBox.SelectedIndex;
                ApplicationDataContainer settings = ApplicationData.Current.LocalSettings;
                settings.Values["AppNavTheme"] = index;
                App.MainWindow?.UpdateNavTheme(index);
            }
            catch { }
        }

        private async void Quarantine_ViewButton_Click(Object sender, RoutedEventArgs e)
        {
            try
            {
                QuarantineDialog dialog = new()
                {
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                };
                await dialog.ShowAsync();
            }
            catch { }
        }

        private async void Quarantine_ClearButton_Click(Object sender, RoutedEventArgs e)
        {
            _ = QuarantineManager.ClearQuarantine();
        }

        private async void Trust_ViewButton_Click(Object sender, RoutedEventArgs e)
        {
            try
            {
                TrustDialog dialog = new()
                {
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                };
                _ = dialog.ShowAsync();
            }
            catch { }
        }

        private async void Trust_AddButton_Click(Object sender, RoutedEventArgs e)
        {
            try
            {
                PickFileResult file = await (new FileOpenPicker(XamlRoot.ContentIslandEnvironment.AppWindowId).PickSingleFileAsync());
                if (file is null) { return; }
                await TrustManager.AddToTrust(file.Path);
            }
            catch { }
        }

        private void TrayVisibleToggle_Toggled(Object sender, RoutedEventArgs e)
        {
            Toggled_SaveToggleData(sender, e);
            App.MainWindow?.manager?.IsVisibleInTray = TrayVisibleToggle.IsEnabled;
        }


        private void SettingsSearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
        {
            if (args.Reason == AutoSuggestionBoxTextChangeReason.UserInput)
            {
                String searchText = sender.Text.ToLowerInvariant();
                if (String.IsNullOrWhiteSpace(searchText))
                {
                    ShowAllSettingsItems();
                    return;
                }
                FilterSettingsItems(searchText);
            }
        }

        private void ShowAllSettingsItems()
        {
            if (SettingsContentPanel == null) return;

            foreach (UIElement child in SettingsContentPanel.Children)
            {
                if (child is FrameworkElement element)
                {
                    element.Visibility = Visibility.Visible;
                    if (element is SettingsExpander expander)
                    {
                        foreach (Object expanderChild in expander.Items)
                        {
                            if (expanderChild is SettingsCard card)
                            {
                                card.Visibility = Visibility.Visible;
                            }
                        }
                    }
                }
            }
            App.PlayEntranceAnimation(SettingsContentPanel, "up", 40);
        }

        private void FilterSettingsItems(String searchText)
        {
            if (SettingsContentPanel == null) return;

            foreach (UIElement child in SettingsContentPanel.Children)
            {
                if (child is FrameworkElement element)
                {
                    element.Visibility = Visibility.Collapsed;
                    if (element is SettingsExpander expander)
                    {
                        foreach (Object expanderChild in expander.Items)
                        {
                            if (expanderChild is SettingsCard card)
                            {
                                card.Visibility = Visibility.Collapsed;
                            }
                        }
                    }
                }
            }

            Boolean currentHeaderMatched = false;
            for (Int32 i = 0; i < SettingsContentPanel.Children.Count; i++)
            {
                UIElement child = SettingsContentPanel.Children[i];
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
                    else if (element is SettingsCard or SettingsExpander)
                    {
                        Boolean shouldShow = false;
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
                            foreach (Object expanderChild in expander.Items)
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
            App.PlayEntranceAnimation(SettingsContentPanel, "up", 40);
        }

        private static Boolean IsSettingsItemMatched(FrameworkElement item, String searchText)
        {
            String itemText = GetSettingsItemText(item);
            if (String.IsNullOrEmpty(itemText))
                return false;
            return itemText.Contains(searchText, StringComparison.InvariantCultureIgnoreCase);
        }

        private static String GetSettingsItemText(FrameworkElement item)
        {
            if (item is TextBlock textBlock)
            {
                return textBlock.Text;
            }
            else if (item is SettingsCard card)
            {
                return card.Header?.ToString() ?? String.Empty;
            }
            else if (item is SettingsExpander expander)
            {
                return expander.Header?.ToString() ?? String.Empty;
            }
            return String.Empty;
        }

        private Boolean DisabledVerifyToggleVerify = true;

        private async void DisabledVerifyToggle_Toggled(Object sender, RoutedEventArgs e)
        {
            if (!DisabledVerifyToggleVerify || IsInitialize) return;

            if (DisabledVerifyToggle.IsOn)
            {
                DisabledVerifyToggleVerify = false;
                DisabledVerifyToggle.IsOn = false;
                UserConsentVerificationResult result = await UserConsentVerifier.RequestVerificationAsync(String.Empty);
                if (result is UserConsentVerificationResult.DeviceNotPresent or
                    UserConsentVerificationResult.DisabledByPolicy or
                    UserConsentVerificationResult.NotConfiguredForUser or
                    UserConsentVerificationResult.Verified)
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

        private async void SelectBackgroundImageButton_Click(Object sender, RoutedEventArgs e)
        {
            try
            {
                var picker = new FileOpenPicker(XamlRoot.ContentIslandEnvironment.AppWindowId)
                {
                    SuggestedStartLocation = PickerLocationId.PicturesLibrary
                };
                picker.FileTypeFilter.Add(".jpg");
                picker.FileTypeFilter.Add(".jpeg");
                picker.FileTypeFilter.Add(".png");
                picker.FileTypeFilter.Add(".bmp");
                picker.FileTypeFilter.Add(".gif");

                PickFileResult file = await picker.PickSingleFileAsync();
                if (file is null)
                {
                    return;
                }

                try
                {
                    String imagePath = file.Path;
                    String key = "background_image";
                    await ApplicationData.WriteFileAsync(key, imagePath);
                    App.MainWindow?.ApplyBackgroundImageAsync(imagePath);
                }
                catch (Exception ex)
                {
                    ContentDialog errorDialog = new()
                    {
                        Title = Localizer.Get().GetLocalizedString("SettingsPage_BackgroundImage_Error_Title"),
                        Content = String.Format(Localizer.Get().GetLocalizedString("SettingsPage_BackgroundImage_SelectError_Content"), ex.Message),
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        XamlRoot = this.XamlRoot
                    };
                    await errorDialog.ShowAsync();
                }
            }
            catch (Exception ex)
            {
                ContentDialog errorDialog = new()
                {
                    Title = Localizer.Get().GetLocalizedString("SettingsPage_BackgroundImage_Error_Title"),
                    Content = String.Format(Localizer.Get().GetLocalizedString("SettingsPage_BackgroundImage_SelectError_Content"), ex.Message),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot
                };
                await errorDialog.ShowAsync();
            }
        }

        private async void ClearBackgroundImageButton_Click(Object sender, RoutedEventArgs e)
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
                ContentDialog errorDialog = new()
                {
                    Title = Localizer.Get().GetLocalizedString("SettingsPage_BackgroundImage_Error_Title"),
                    Content = String.Format(Localizer.Get().GetLocalizedString("SettingsPage_BackgroundImage_ClearError_Content"), ex.Message),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot
                };
                await errorDialog.ShowAsync();
            }
        }

        private async void OpenConfigLocationButton_Click(Object sender, RoutedEventArgs e)
        {
            try
            {
                String path = ApplicationData.LocalFolder.Path;
                await Windows.System.Launcher.LaunchFolderPathAsync(path);
            }
            catch (Exception ex)
            {
                ContentDialog errorDialog = new()
                {
                    Title = Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Location_OpenFailed_Title"),
                    Content = String.Format(Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Location_OpenFailed_Content"), ex.Message),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot
                };
                await errorDialog.ShowAsync();
            }
        }

        private async void ResetConfigButton_Click(Object sender, RoutedEventArgs e)
        {
            ContentDialog confirmDialog = new()
            {
                Title = Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Reset_Confirm_Title"),
                Content = Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Reset_Confirm_Content"),
                PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                XamlRoot = this.XamlRoot,
                DefaultButton = ContentDialogButton.Close
            };

            if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary)
            {
                try
                {
                    String path = ApplicationData.LocalFolder.Path;
                    if (Directory.Exists(path))
                    {
                        Directory.Delete(path, true);
                    }
                }
                catch (Exception ex)
                {
                    ContentDialog errorDialog = new()
                    {
                        Title = Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Reset_DeleteFailed_Title"),
                        Content = String.Format(Localizer.Get().GetLocalizedString("SettingsPage_Other_Config_Reset_DeleteFailed_Content"), ex.Message),
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        XamlRoot = this.XamlRoot
                    };
                    await errorDialog.ShowAsync();
                    return;
                }

                try
                {
                    String? current = Process.GetCurrentProcess().MainModule?.FileName;
                    if (!String.IsNullOrEmpty(current))
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

        private void BackgroundImageOpacitySlider_ValueChanged(Object sender, RoutedEventArgs e)
        {
            if (IsInitialize || sender is not Slider slider) return;

            ApplicationDataContainer settings = ApplicationData.Current.LocalSettings;
            settings.Values["AppBackgroundImageOpacity"] = slider.Value;

            App.MainWindow?.UpdateBackgroundImageOpacity(slider.Value / 100.0);
        }

        private async void Boot_Save_Button_Click(Object sender, RoutedEventArgs e)
        {
            try
            {
                Byte[] mbr = Helper.DiskOperator.ReadBootSector(0);
                if (mbr.Length == 0) return;
                FileSavePicker picker = new(XamlRoot.ContentIslandEnvironment.AppWindowId)
                {
                    SuggestedFileName = "Data",
                    DefaultFileExtension = ".bin",
                    SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
                    SuggestedFolder = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                };

                PickFileResult file = await picker.PickSaveFileAsync();
                if (file is null) { return; }

                _ = File.WriteAllBytesAsync(file.Path, mbr);
            }
            catch { }
        }
    }
}
