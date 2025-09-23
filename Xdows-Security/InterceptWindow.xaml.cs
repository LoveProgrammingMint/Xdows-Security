using Microsoft.Diagnostics.Tracing.StackSources;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.UI.Xaml.Shapes;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Xdows.ScanEngine;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Xdows_Security
{
    public sealed partial class InterceptWindow : Window
    {
        private string? _originalFilePath;
        private string? _virusFilePath;

        public static void ShowOrActivate(string path)
        {
            var w = new InterceptWindow();
            try { w.Activate(); } catch { }
            w.SetFileInfo(path);
            //SetIcon("logo.ico");
        }

        private void SetFileInfo(string path)
        {
            _originalFilePath = path;
            _virusFilePath = path + (File.Exists(path) ? "" : ".virus");
            System.Diagnostics.Debug.WriteLine(_virusFilePath);
            ProcessPath.Text = path;
            ProcessName.Text = System.IO.Path.GetFileName(path);
            
            try
            {
                var fileInfo = new FileInfo(_virusFilePath);
                ModifyDate.Text = fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss");
            }
            catch
            {
                ModifyDate.Text = "未知";
            }
            
            SecurityAdvice.Text = "检测到可疑程序，建议立即删除或隔离处理。";
            
            try
            {
                FileIcon.Source = SetIcon(_virusFilePath);
            }
            catch
            {
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
                // 删除 .virus 文件
                if (File.Exists(_virusFilePath))
                {
                    File.Delete(_virusFilePath);
                    await ShowMessageDialog("删除成功", "文件已成功删除。");
                    this.Close();
                }
                else
                {
                    await ShowMessageDialog("文件不存在", "要删除的文件不存在。");
                }
            }
            catch (Exception ex)
            {
                await ShowMessageDialog("删除失败", $"删除文件时出错：{ex.Message}");
            }
        }

        private async Task RestoreFile()
        {
            try
            {
                if (File.Exists(_virusFilePath))
                {
                    // 恢复文件：删除 .virus 后缀
                    string restoredPath = _virusFilePath.Replace(".virus", "");
                    
                    // 如果原文件已存在，先删除
                    if (File.Exists(restoredPath))
                    {
                        File.Delete(restoredPath);
                    }
                    
                    File.Move(_virusFilePath, restoredPath);
                    
                    await ShowMessageDialog("恢复成功", "文件已成功恢复。");
                    this.Close();
                }
                else
                {
                    await ShowMessageDialog("文件不存在", "要恢复的文件不存在。");
                }
            }
            catch (Exception ex)
            {
                await ShowMessageDialog("恢复失败", $"恢复文件时出错：{ex.Message}");
            }
        }

        private async void DisableProtection()
        {
            var result = await ShowConfirmationDialog("关闭防护", 
                "确定要关闭安全防护吗？这将使您的系统面临安全风险。");
            
            if (result)
            {
                await ShowMessageDialog("防护已关闭", "安全防护已暂时关闭。");
                this.Close();
            }
        }

        private async Task<bool> ShowConfirmationDialog(string title, string message)
        {
            ContentDialog dialog = new ContentDialog
            {
                Title = title,
                Content = message,
                PrimaryButtonText = "确定",
                SecondaryButtonText = "取消",
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
                PrimaryButtonText = "确定",
                XamlRoot = this.Content.XamlRoot
            };

            await dialog.ShowAsync();
        }
    }
}