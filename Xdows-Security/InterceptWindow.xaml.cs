using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using WinUI3Localizer;
using System;
using System.IO;
using System.Threading.Tasks;
namespace Xdows_Security
{
    public sealed partial class InterceptWindow : Window
    {
        private string? _originalFilePath;
        private string? _virusFilePath;

        public static void ShowOrActivate(string path)
        {
            var w = new InterceptWindow();
            w.SetFileInfo(path);
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
                    ModifyDate.Text = Localizer.Get().GetLocalizedString("AllPage_Undefined.Text");
                }
            }
            catch (Exception ex)
            {
                ModifyDate.Text = Localizer.Get().GetLocalizedString("AllPage_Undefined.Text");
                LogText.AddNewLog(3, "InterceptWindow - SetFileInfo", ex.Message);
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
                LogText.AddNewLog(3, "InterceptWindow - LoadIcon", ex.Message);
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

        public InterceptWindow()
        {
            InitializeComponent();
            var manager = WinUIEx.WindowManager.Get(this);
            manager.MinWidth = 500;
            manager.MinHeight = 400;
            manager.Width = 700;
            manager.Height = 600;
            try
            {
                Localizer.Get().LanguageChanged += Localizer_LanguageChanged;
                UpdateWindowTitle();
            }
            catch { }

            this.Closed += (_, __) => Localizer.Get().LanguageChanged -= Localizer_LanguageChanged;
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
                switch (menuItem.Tag.ToString())
                {
                    case "Delete":
                        await DeleteFile();
                        break;
                    case "Restore":
                        await RestoreFile();
                        break;
                    case "Disable":
                        DisableProtection();
                        break;
                }
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
                LogText.AddNewLog(3, "InterceptWindow - DeleteFile - Failed", ex.ToString());
            }
        }

        private async Task RestoreFile()
        {
            try
            {
                if (File.Exists(_virusFilePath))
                {
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
            catch (Exception ex)
            {
                await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Restore_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Restore_Failed_Message"));
                LogText.AddNewLog(3, "InterceptWindow - RestoreFile - Failed", ex.ToString());
            }
        }

        private async void DisableProtection()
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
                XamlRoot = this.Content.XamlRoot
            };

            var result = await dialog.ShowAsync();
            return result == ContentDialogResult.Primary;
        }

        private async Task ShowMessageDialog(string title, string message)
        {
            ContentDialog dialog = new ContentDialog
            {
                Title = title,
            Content = message,
            PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                XamlRoot = this.Content.XamlRoot
            };

            await dialog.ShowAsync();
        }
    }
}