using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
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
                    ModifyDate.Text = "未知";
                }
            }
            catch (Exception ex)
            {
                ModifyDate.Text = "未知";
                LogText.AddNewLog(3, "InterceptWindow - SetFileInfo", ex.Message);
            }
            
            SecurityAdvice.Text = "��⵽���ɳ��򣬽�������ɾ������봦����";
            
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
                // ɾ�� .virus �ļ�
                if (File.Exists(_virusFilePath))
                {
                    File.Delete(_virusFilePath);
                    await ShowMessageDialog("ɾ���ɹ�", "�ļ��ѳɹ�ɾ����");
                    this.Close();
                }
                else
                {
                    await ShowMessageDialog("�ļ�������", "Ҫɾ�����ļ������ڡ�");
                }
            }
            catch (Exception ex)
            {
                await ShowMessageDialog("删除失败", $"删除文件时出错：{ex.Message}。请确认您有足够权限或文件未被占用。");
                LogText.AddNewLog(3, "InterceptWindow - DeleteFile - Failed", ex.ToString());
            }
        }

        private async Task RestoreFile()
        {
            try
            {
                if (File.Exists(_virusFilePath))
                {
                    // �ָ��ļ���ɾ�� .virus ��׺
                    string restoredPath = _virusFilePath.Replace(".virus", "");
                    
                    // ���ԭ�ļ��Ѵ��ڣ���ɾ��
                    if (File.Exists(restoredPath))
                    {
                        File.Delete(restoredPath);
                    }
                    
                    File.Move(_virusFilePath, restoredPath);
                    
                    await ShowMessageDialog("�ָ��ɹ�", "�ļ��ѳɹ��ָ���");
                    this.Close();
                }
                else
                {
                    await ShowMessageDialog("�ļ�������", "Ҫ�ָ����ļ������ڡ�");
                }
            }
            catch (Exception ex)
            {
                await ShowMessageDialog("恢复失败", $"恢复文件时出错：{ex.Message}。请确认您有足够权限。\n{ex.Message}");
                LogText.AddNewLog(3, "InterceptWindow - RestoreFile - Failed", ex.ToString());
            }
        }

        private async void DisableProtection()
        {
            var result = await ShowConfirmationDialog("�رշ���", 
                "ȷ��Ҫ�رհ�ȫ�������⽫ʹ����ϵͳ���ٰ�ȫ���ա�");
            
            if (result)
            {
                await ShowMessageDialog("�����ѹر�", "��ȫ��������ʱ�رա�");
                this.Close();
            }
        }

        private async Task<bool> ShowConfirmationDialog(string title, string message)
        {
            ContentDialog dialog = new ContentDialog
            {
                Title = title,
                Content = message,
                PrimaryButtonText = "ȷ��",
                SecondaryButtonText = "ȡ��",
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
                PrimaryButtonText = "ȷ��",
                XamlRoot = this.Content.XamlRoot
            };

            await dialog.ShowAsync();
        }
    }
}