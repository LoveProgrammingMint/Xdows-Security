using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using TrustQuarantine;
using WinUI3Localizer;

namespace Xdows_Security
{
    public sealed partial class InterceptWindow : Window
    {
        private readonly string? _originalFilePath;
        private readonly string? _type;

        private static readonly Dictionary<string, InterceptWindow> _openWindows = [];

        public static void ShowOrActivate(bool isSucceed, string path, string type)
        {
            string key = $"{path}|{type}";
            if (_openWindows.TryGetValue(key, out var existingWindow))
            {
                try
                {
                    existingWindow.Activate();
                    return;
                }
                catch
                {
                    _openWindows.Remove(key);
                }
            }
            var w = new InterceptWindow(isSucceed, path, type, key);
            w.Activate();
            // SetIcon("logo.ico");
        }

        private InterceptWindow(bool isSucceed, string path, string type, string key)
        {
            this.InitializeComponent();
            var manager = WinUIEx.WindowManager.Get(this);
            manager.MinWidth = 500;
            manager.MinHeight = 400;
            manager.Width = 700;
            manager.Height = 600;
            _originalFilePath = path;
            // 将窗口添加到静态字典
            _openWindows[key] = this;
            try
            {
                Localizer.Get().LanguageChanged += Localizer_LanguageChanged;
                UpdateWindowTitle();
            }
            catch { }
            this.Closed += (sender, e) =>
            {
                Localizer.Get().LanguageChanged -= Localizer_LanguageChanged;
                _openWindows.Remove(key);
            };
            _type = type;
            if (_type == "Reg")
            {
                EngineNameText.Text = Localizer.Get().GetLocalizedString("InterceptWindow_EngineName_Registry");
            }
            if (_type == "Reg")
            {
                ScanButton.IsEnabled = false;
                SecurityAdviceBox.Visibility = Visibility.Collapsed;
                Grid.SetColumn(EngineBox, 0);
            }
            UpdateWindowTitle();
            InitializeUI(path);
        }

        private void Localizer_LanguageChanged(object? sender, WinUI3Localizer.LanguageChangedEventArgs e)
        {
            DispatcherQueue.TryEnqueue(() => UpdateWindowTitle());
        }

        private void UpdateWindowTitle()
        {
            try
            {
                var title = Localizer.Get().GetLocalizedString("InterceptWindow_WindowTitle");
                if (!string.IsNullOrEmpty(title))
                    this.Title = title;
            }
            catch { }
        }

        private async void MenuFlyoutItem_Click(object sender, RoutedEventArgs e)
        {
            if (sender is MenuFlyoutItem menuItem)
            {
                var tag = menuItem.Tag?.ToString();
                switch (tag)
                {
                    case "Delete":
                        await DeleteFile();
                        break;
                    case "Restore":
                        await RestoreFile();
                        break;
                    case "Disable":
                        await DisableProtection();
                        break;
                    case "Trust":
                        await AddToTrust();
                        break;
                    default:
                        break;
                }
            }
        }

        private async Task AddToTrust()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(_originalFilePath))
                {
                    await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Message"));
                    return;
                }
                var quarantineItems = QuarantineManager.GetQuarantineItems();
                var qi = quarantineItems.Find(q => string.Equals(q.SourcePath, _originalFilePath, StringComparison.OrdinalIgnoreCase));
                if (qi != null)
                {
                    bool added = await TrustManager.AddToTrustByHash(_originalFilePath, qi.FileHash);
                    if (!added)
                    {
                        await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Message"));
                        return;
                    }
                    bool restored = await QuarantineManager.RestoreFile(qi.FileHash);
                    if (restored)
                    {
                        await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Success_Title"), string.Format(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Success_Message"), _originalFilePath));
                        this.Close();
                        return;
                    }
                    await TrustManager.RemoveFromTrust(_originalFilePath);
                    await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Message"));
                    return;
                }

                if (File.Exists(_originalFilePath))
                {
                    bool success = await TrustManager.AddToTrust(_originalFilePath);
                    if (success)
                    {
                        await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Success_Title"), string.Format(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Success_Message"), _originalFilePath));
                        this.Close();
                        return;
                    }
                    else
                    {
                        await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Message"));
                        return;
                    }
                }

                await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Message"));
            }
            catch (Exception ex)
            {
                await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Message"));
                LogText.AddNewLog(LogLevel.ERROR, "InterceptWindow - AddToTrust - Failed", ex.ToString());
            }
        }

        private async Task DeleteFile()
        {
            try
            {
                var quarantineItems = QuarantineManager.GetQuarantineItems();
                var item = quarantineItems.Find(q => string.Equals(q.SourcePath, _originalFilePath, StringComparison.OrdinalIgnoreCase));
                if (item != null)
                {
                    bool success = await QuarantineManager.DeleteItem(item.FileHash);
                    if (success)
                    {
                        await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Delete_Success_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Delete_Success_Message"));
                        this.Close();
                        return;
                    }
                    else
                    {
                        await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Delete_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Delete_Failed_Message"));
                        return;
                    }
                }

                await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Delete_NoFile_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Delete_NoFile_Message"));
            }
            catch (Exception ex)
            {
                await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Delete_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Delete_Failed_Message"));
                LogText.AddNewLog(LogLevel.ERROR, "InterceptWindow - DeleteFile - Failed", ex.ToString());
            }
        }

        private async Task RestoreFile()
        {
            try
            {
                if (_type != "Reg")
                {
                    // 文件类型的恢复逻辑：仅使用隔离区恢复，不依赖任何本地后缀或本地文件
                    var quarantineItems = QuarantineManager.GetQuarantineItems();
                    QuarantineItemModel? found = null;

                    if (!string.IsNullOrWhiteSpace(_originalFilePath))
                    {
                        found = quarantineItems.Find(q => string.Equals(q.SourcePath, _originalFilePath, StringComparison.OrdinalIgnoreCase));
                    }

                    if (found != null)
                    {
                        bool success = await QuarantineManager.RestoreFile(found.FileHash);
                        if (success)
                        {
                            await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Restore_Success_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Restore_Success_Message"));
                            this.Close();
                            return;
                        }
                        else
                        {
                            await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Restore_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Restore_Failed_Message"));
                            return;
                        }
                    }

                    // 隔离区中未找到对应项，提示未找到文件
                    await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Restore_NoFile_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Restore_NoFile_Message"));
                }
            }
            catch (Exception ex)
            {
                await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Restore_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Restore_Failed_Message"));
                LogText.AddNewLog(LogLevel.ERROR, "InterceptWindow - RestoreFile - Failed", ex.ToString());
            }
        }

        private async Task DisableProtection()
        {
            var loc = Localizer.Get();
            var title = loc.GetLocalizedString("InterceptWindow_Disable_Confirm_Title");
            var msg = loc.GetLocalizedString("InterceptWindow_Disable_Confirm_Message");
            var result = await ShowConfirmationDialog(title, msg);

            if (result)
            {
                await ShowMessageDialog(loc.GetLocalizedString("InterceptWindow_Disable_Success_Title"), loc.GetLocalizedString("InterceptWindow_Disable_Success_Message"));
                this.Close();
            }
        }

        private async Task<bool> ShowConfirmationDialog(string title, string message)
        {
            ContentDialog dialog = new()
            {
                Title = title,
                Content = message,
                PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                SecondaryButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"],
                XamlRoot = this.Content.XamlRoot
            };

            var result = await dialog.ShowAsync();
            return result == ContentDialogResult.Primary;
        }

        private void InitializeUI(string path)
        {
            ProcessPath.Text = path;
            ProcessName.Text = System.IO.Path.GetFileName(path);
        }

        private async Task ShowMessageDialog(string title, string message)
        {
            ContentDialog dialog = new()
            {
                Title = title,
                Content = message,
                PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"],
                XamlRoot = this.Content.XamlRoot
            };

            await dialog.ShowAsync();
        }
    }
}