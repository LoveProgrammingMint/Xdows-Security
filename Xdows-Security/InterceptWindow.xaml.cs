using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using WinUI3Localizer;

namespace Xdows_Security
{
    public sealed partial class InterceptWindow : Window
    {
        private string? _originalFilePath;
        private string? _virusFilePath;
        private readonly string? _type;

        // 静态字典用于跟踪已打开的窗口
        private static readonly Dictionary<string, InterceptWindow> _openWindows = new Dictionary<string, InterceptWindow>();

        public static void ShowOrActivate(bool isSucceed, string path, string type)
        {
            // 创建唯一的键（路径+类型）
            string key = $"{path}|{type}";

            // 如果已经存在相同文件的窗口，激活它而不是创建新窗口
            if (_openWindows.TryGetValue(key, out var existingWindow))
            {
                try
                {
                    existingWindow.Activate();
                    return;
                }
                catch
                {
                    // 如果窗口已关闭但未从字典中移除，移除它
                    _openWindows.Remove(key);
                }
            }

            // 创建新窗口
            var w = new InterceptWindow(isSucceed, path, type, key);
            w.Activate();
            // SetIcon("logo.ico");
        }

        private void SetFileInfo(string path)
        {
            _originalFilePath = path;
            if (File.Exists(path))
                _virusFilePath = path;
            else if (File.Exists(path + ".virus"))
                _virusFilePath = path + ".virus";
            else
                _virusFilePath = path;
            System.Diagnostics.Debug.WriteLine(_virusFilePath);
            ProcessPath.Text = path;
            ProcessName.Text = System.IO.Path.GetFileName(path);

            try
            {
                if (File.Exists(_virusFilePath))
                {
                    var fileInfo = new FileInfo(_virusFilePath);
                    ModifyDate.Text = fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss");
                }
                else
                {
                    ModifyDate.Text = Localizer.Get().GetLocalizedString("AllPage_Undefined");
                }
            }
            catch (Exception ex)
            {
                ModifyDate.Text = Localizer.Get().GetLocalizedString("AllPage_Undefined");
                LogText.AddNewLog(LogLevel.ERROR, "InterceptWindow - SetFileInfo", ex.Message);
            }

            try
            {
                if (File.Exists(_virusFilePath))
                {
                    FileIcon.Source = SetIcon(_virusFilePath);
                }
                else
                {
                    // fallback: keep default or placeholder icon
                }
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogLevel.ERROR, "InterceptWindow - LoadIcon", ex.Message);
            }
        }

        public Microsoft.UI.Xaml.Media.Imaging.BitmapImage SetIcon(string path)
        {
            var fileIcon = System.Drawing.Icon.ExtractAssociatedIcon(path);
            if (fileIcon == null) return new Microsoft.UI.Xaml.Media.Imaging.BitmapImage();
            using (var bitmap = fileIcon.ToBitmap())
            {
                using (var memoryStream = new System.IO.MemoryStream())
                {
                    bitmap.Save(memoryStream, System.Drawing.Imaging.ImageFormat.Png);
                    memoryStream.Position = 0;

                    var bitmapImage = new Microsoft.UI.Xaml.Media.Imaging.BitmapImage();
                    bitmapImage.SetSource(memoryStream.AsRandomAccessStream());
                    return bitmapImage;
                }
            }
        }

        private InterceptWindow(bool isSucceed, string path, string type, string key)
        {
            this.InitializeComponent();
            var manager = WinUIEx.WindowManager.Get(this);
            manager.MinWidth = 500;
            manager.MinHeight = 400;
            manager.Width = 700;
            manager.Height = 600;

            // 将窗口添加到静态字典
            _openWindows[key] = this;

            try
            {
                Localizer.Get().LanguageChanged += Localizer_LanguageChanged;
                UpdateWindowTitle();
            }
            catch { }

            // 注册窗口关闭事件，从字典中移除
            this.Closed += (sender, e) =>
            {
                Localizer.Get().LanguageChanged -= Localizer_LanguageChanged;
                _openWindows.Remove(key);
            };

            SetFileInfo(path);
            _type = type;

            // 根据类型设置图标
            if (_type == "Reg")
            {
                // 使用系统注册表编辑器图标
                try
                {
                    string regeditPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "regedit.exe");
                    if (File.Exists(regeditPath))
                    {
                        FileIcon.Source = SetIcon(regeditPath);
                    }
                    else
                    {
                        FileIcon.Source = SetIcon(path);
                    }
                }
                catch
                {
                    // 如果获取失败，使用默认图标
                    if (File.Exists(path))
                    {
                        FileIcon.Source = SetIcon(path);
                    }
                }
            }
            else
            {
                // 原有的动态获取图标逻辑
                if (File.Exists(path))
                {
                    FileIcon.Source = SetIcon(path);
                }
            }

            // 根据类型调整界面文本
            if (_type == "Reg")
            {
                // 将"SouXiao 引擎"文本更改为"内置规则"
                EngineNameText.Text = Localizer.Get().GetLocalizedString("InterceptWindow_EngineName_Registry");
            }

            // 根据类型调整按钮状态
            if (_type == "Reg")
            {
                ScanButton.IsEnabled = false;
                ModifyDateBox.Visibility = Visibility.Collapsed;
                SecurityAdviceBox.Visibility = Visibility.Collapsed;
                Grid.SetColumn(EngineBox, 0);
            }

            // 更新本地化标题
            UpdateWindowTitle();

            // 初始化其他UI元素
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
                await (menuItem.Tag.ToString() switch
                {
                    "Delete" => DeleteFile(),
                    "Restore" => RestoreFile(),
                    "Disable" => DisableProtection(),
                    _ => Task.CompletedTask
                });
            }
        }

        private async Task DeleteFile()
        {
            try
            {
                if (File.Exists(_virusFilePath))
                {
                    File.Delete(_virusFilePath);
                    await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Delete_Success_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Delete_Success_Message"));
                    this.Close();
                }
                else
                {
                    await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Delete_NoFile_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Delete_NoFile_Message"));
                }
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
                    // 文件类型的恢复逻辑
                    if (File.Exists(_virusFilePath))
                    {
                        // 检查是否是隔离区文件
                        if (_virusFilePath.EndsWith(".virus"))
                        {
                            // 尝试从隔离区恢复文件
                            string quarantinePath = _virusFilePath;
                            string originalPath = _originalFilePath ?? string.Empty;

                            // 尝试从隔离区管理器恢复文件
                            var quarantineItems = Protection.QuarantineManager.GetQuarantineItems();
                            var quarantineItem = quarantineItems.Find(q => q.QuarantinePath == quarantinePath || q.OriginalPath == originalPath);

                            if (quarantineItem != null)
                            {
                                // 从隔离区恢复文件
                                string itemId = Path.GetFileName(quarantineItem.QuarantinePath);
                                bool success = Protection.QuarantineManager.RestoreFromQuarantine(itemId);

                                if (success)
                                {
                                    await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Restore_Success_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Restore_Success_Message"));
                                    this.Close();
                                    return;
                                }
                            }
                        }

                        // 如果不是隔离区文件或隔离区恢复失败，使用原有逻辑
                        string restoredPath = _virusFilePath.Replace(".virus", "");

                        if (File.Exists(restoredPath))
                        {
                            File.Delete(restoredPath);
                        }

                        File.Move(_virusFilePath, restoredPath);

                        await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Restore_Success_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Restore_Success_Message"));
                        this.Close();
                    }
                    else
                    {
                        await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Restore_NoFile_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Restore_NoFile_Message"));
                    }
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
            ContentDialog dialog = new ContentDialog
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
            // 设置文件路径和名称
            ProcessPath.Text = path;
            ProcessName.Text = System.IO.Path.GetFileName(path);

            try
            {
                if (File.Exists(_virusFilePath))
                {
                    var fileInfo = new FileInfo(_virusFilePath);
                    ModifyDate.Text = fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss");
                }
                else
                {
                    ModifyDate.Text = Localizer.Get().GetLocalizedString("AllPage_Undefined");
                }
            }
            catch (Exception ex)
            {
                ModifyDate.Text = Localizer.Get().GetLocalizedString("AllPage_Undefined");
                LogText.AddNewLog(LogLevel.ERROR, "InterceptWindow - InitializeUI", ex.Message);
            }
        }

        private async Task ShowMessageDialog(string title, string message)
        {
            ContentDialog dialog = new ContentDialog
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