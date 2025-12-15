using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.WindowsAPICodePack.Dialogs;
using System;
using System.IO;
using WinUI3Localizer;
using Xdows.Protection;

namespace Xdows_Security
{
    public sealed partial class AddTrustDialog : ContentDialog
    {
        private TrustItemType _selectedType = TrustItemType.File;

        public new string Title => Localizer.Get().GetLocalizedString("AddTrustDialog_Title");
        public new string PrimaryButtonText => Localizer.Get().GetLocalizedString("AddTrustDialog_AddButton");
        public new string CloseButtonText => Localizer.Get().GetLocalizedString("AddTrustDialog_CancelButton");

        public AddTrustDialog()
        {
            this.InitializeComponent();
            this.Opened += AddTrustDialog_Opened;
            this.PrimaryButtonClick += AddTrustDialog_PrimaryButtonClick;
            UpdatePreview();
        }

        /// <summary>
        /// 对话框打开事件
        /// </summary>
        private void AddTrustDialog_Opened(ContentDialog sender, ContentDialogOpenedEventArgs args)
        {
            UpdatePreview();
        }

        /// <summary>
        /// 主按钮点击事件
        /// </summary>
        private void AddTrustDialog_PrimaryButtonClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
        {
            string path = PathTextBox.Text.Trim();
            string note = NoteTextBox.Text.Trim();

            if (string.IsNullOrEmpty(path))
            {
                args.Cancel = true;
                StatusText.Text = Localizer.Get().GetLocalizedString("AddTrustDialog_Error_SelectFile");
                return;
            }

            try
            {
                // 根据类型添加到信任区
                bool success = false;
                if (_selectedType == TrustItemType.File)
                {
                    success = TrustManager.AddFileToTrust(path, note);
                }
                else
                {
                    success = TrustManager.AddFolderToTrust(path, note);
                }

                if (!success)
                {
                    args.Cancel = true;
                    StatusText.Text = Localizer.Get().GetLocalizedString("AddTrustDialog_Error_AddFailed");
                }
            }
            catch (Exception ex)
            {
                args.Cancel = true;
                StatusText.Text = $"{Localizer.Get().GetLocalizedString("AddTrustDialog_Error_AddFailed")}: {ex.Message}";
            }
        }

        /// <summary>
        /// 路径文本框内容变化事件
        /// </summary>
        private void PathTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            UpdatePreview();
        }

        /// <summary>
        /// 类型单选按钮选中事件
        /// </summary>
        private void TypeRadioButton_Checked(object sender, RoutedEventArgs e)
        {
            if (FileRadioButton.IsChecked == true)
            {
                _selectedType = TrustItemType.File;
            }
            else if (FolderRadioButton.IsChecked == true)
            {
                _selectedType = TrustItemType.Folder;
            }

            UpdatePreview();
        }

        /// <summary>
        /// 浏览按钮点击事件
        /// </summary>
        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_selectedType == TrustItemType.File)
                {
                    using var filePicker = new CommonOpenFileDialog
                    {
                        Title = Localizer.Get().GetLocalizedString("AddTrustDialog_SelectFile_Title"),
                        IsFolderPicker = false,
                        EnsurePathExists = true,
                        Multiselect = false
                    };

                    // 添加所有文件类型过滤器
                    filePicker.Filters.Add(new CommonFileDialogFilter(
                        Localizer.Get().GetLocalizedString("AddTrustDialog_AllFiles_Filter"), "*.*"));

                    if (filePicker.ShowDialog() == CommonFileDialogResult.Ok)
                    {
                        PathTextBox.Text = filePicker.FileName;
                    }
                }
                else
                {
                    using var folderPicker = new CommonOpenFileDialog
                    {
                        Title = Localizer.Get().GetLocalizedString("AddTrustDialog_SelectFolder_Title"),
                        IsFolderPicker = true,
                        EnsurePathExists = true
                    };

                    if (folderPicker.ShowDialog() == CommonFileDialogResult.Ok)
                    {
                        PathTextBox.Text = folderPicker.FileName;
                    }
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = $"{Localizer.Get().GetLocalizedString("AddTrustDialog_Error_BrowseFailed")}: {ex.Message}";
            }
        }

        /// <summary>
        /// 更新预览信息
        /// </summary>
        private void UpdatePreview()
        {
            string path = PathTextBox.Text.Trim();

            // 确保PreviewText不为null
            if (PreviewText == null)
            {
                return;
            }

            if (string.IsNullOrEmpty(path))
            {
                PreviewText.Text = Localizer.Get().GetLocalizedString("AddTrustDialog_Preview_SelectFile");
                StatusText.Text = "";
                IsPrimaryButtonEnabled = false;
                return;
            }

            try
            {
                string typeText = _selectedType == TrustItemType.File ? Localizer.Get().GetLocalizedString("AddTrustDialog_Type_File") : Localizer.Get().GetLocalizedString("AddTrustDialog_Type_Folder");
                string typeLabel = Localizer.Get().GetLocalizedString("AddTrustDialog_Label_Type");
                string nameLabel = Localizer.Get().GetLocalizedString("AddTrustDialog_Label_Name");
                string pathLabel = Localizer.Get().GetLocalizedString("AddTrustDialog_Label_Path");
                string sizeLabel = Localizer.Get().GetLocalizedString("AddTrustDialog_Label_Size");
                string containsLabel = Localizer.Get().GetLocalizedString("AddTrustDialog_Label_Contains");
                string fileLabel = Localizer.Get().GetLocalizedString("AddTrustDialog_Label_File");
                string folderLabel = Localizer.Get().GetLocalizedString("AddTrustDialog_Label_Folder");
                string fileExistsText = Localizer.Get().GetLocalizedString("AddTrustDialog_Status_FileExists");
                string fileNotExistsText = Localizer.Get().GetLocalizedString("AddTrustDialog_Status_FileNotExists");
                string folderExistsText = Localizer.Get().GetLocalizedString("AddTrustDialog_Status_FolderExists");
                string folderNotExistsText = Localizer.Get().GetLocalizedString("AddTrustDialog_Status_FolderNotExists");

                if (_selectedType == TrustItemType.File)
                {
                    if (File.Exists(path))
                    {
                        var fileInfo = new FileInfo(path);
                        PreviewText.Text = $"{typeLabel}: {typeText}\n{nameLabel}: {fileInfo.Name}\n{pathLabel}: {path}\n{sizeLabel}: {FormatFileSize(fileInfo.Length)}";
                        StatusText.Text = fileExistsText;
                        IsPrimaryButtonEnabled = true;
                    }
                    else
                    {
                        PreviewText.Text = $"{typeLabel}: {typeText}\n{pathLabel}: {path}";
                        StatusText.Text = fileNotExistsText;
                        IsPrimaryButtonEnabled = false;
                    }
                }
                else
                {
                    if (Directory.Exists(path))
                    {
                        var dirInfo = new DirectoryInfo(path);
                        int fileCount = Directory.GetFiles(path).Length;
                        int dirCount = Directory.GetDirectories(path).Length;

                        PreviewText.Text = $"{typeLabel}: {typeText}\n{nameLabel}: {dirInfo.Name}\n{pathLabel}: {path}\n{containsLabel}: {fileCount} {fileLabel}, {dirCount} {folderLabel}";
                        StatusText.Text = folderExistsText;
                        IsPrimaryButtonEnabled = true;
                    }
                    else
                    {
                        PreviewText.Text = $"{typeLabel}: {typeText}\n{pathLabel}: {path}";
                        StatusText.Text = folderNotExistsText;
                        IsPrimaryButtonEnabled = false;
                    }
                }
            }
            catch (Exception ex)
            {
                PreviewText.Text = $"{Localizer.Get().GetLocalizedString("AddTrustDialog_Label_Path")}: {path}";
                StatusText.Text = $"{Localizer.Get().GetLocalizedString("AddTrustDialog_Status_Error")}: {ex.Message}";
                IsPrimaryButtonEnabled = false;
            }
        }

        /// <summary>
        /// 格式化文件大小
        /// </summary>
        private string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }
    }
}