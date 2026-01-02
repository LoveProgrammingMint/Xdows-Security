using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Protection;
using System;
using System.Collections.Generic;
using System.IO;
using WinUI3Localizer;

namespace Xdows.UI.Dialogs
{
    public sealed partial class QuarantineDialog : ContentDialog
    {
        private List<QuarantineItem> _quarantineItems = [];

        // 本地化属性
        public string DialogTitle => Localizer.Get().GetLocalizedString("QuarantineDialog_Title");
        public string DialogCloseButtonText => Localizer.Get().GetLocalizedString("Button_Confirm");
        public string CountText
        {
            get
            {
                string format = Localizer.Get().GetLocalizedString("QuarantineDialog_TotalItems");
                return string.Format(format, _quarantineItems.Count);
            }
        }

        public QuarantineDialog()
        {
            this.InitializeComponent();
            this.Opened += QuarantineDialog_Opened;
        }

        /// <summary>
        /// 内容对话框打开事件
        /// </summary>
        private void QuarantineDialog_Opened(ContentDialog sender, ContentDialogOpenedEventArgs args)
        {
            // 每次打开对话框时刷新列表
            LoadQuarantineItems();
        }

        /// <summary>
        /// 加载隔离区项目
        /// </summary>
        private void LoadQuarantineItems()
        {
            try
            {
                _quarantineItems = QuarantineManager.GetQuarantineItems();
                QuarantineListView.ItemsSource = _quarantineItems;

                // 通知绑定更新
                this.Bindings.Update();

                // 如果没有项目，禁用清空按钮
                ClearAllButton.IsEnabled = _quarantineItems.Count > 0;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"加载隔离区项目失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 恢复按钮点击事件
        /// </summary>
        private async void RestoreButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is QuarantineItem item)
            {
                try
                {
                    // 从隔离区路径中提取ID
                    if (string.IsNullOrEmpty(item.QuarantinePath))
                    {
                        ShowResultTip(
                            Localizer.Get().GetLocalizedString("QuarantineDialog_OperationFailed"),
                            Localizer.Get().GetLocalizedString("QuarantineDialog_InvalidPath"),
                            button);
                        return;
                    }

                    string fileName = Path.GetFileName(item.QuarantinePath);
                    if (string.IsNullOrEmpty(fileName))
                    {
                        ShowResultTip(
                            Localizer.Get().GetLocalizedString("QuarantineDialog_OperationFailed"),
                            Localizer.Get().GetLocalizedString("QuarantineDialog_InvalidPath"),
                            button);
                        return;
                    }

                    string[] pathParts = fileName.Split('_');
                    if (pathParts.Length == 0)
                    {
                        ShowResultTip(
                            Localizer.Get().GetLocalizedString("QuarantineDialog_OperationFailed"),
                            Localizer.Get().GetLocalizedString("QuarantineDialog_InvalidPath"),
                            button);
                        return;
                    }

                    string itemId = pathParts[0];

                    // 恢复文件
                    bool success = QuarantineManager.RestoreFromQuarantine(itemId);

                    if (success)
                    {
                        // 刷新列表
                        LoadQuarantineItems();

                        // 显示成功提示
                        ShowResultTip(
                            Localizer.Get().GetLocalizedString("QuarantineDialog_Restore_Success_Title"),
                            Localizer.Get().GetLocalizedString("QuarantineDialog_Restore_Success_Message"),
                            button);
                    }
                    else
                    {
                        ShowResultTip(
                            Localizer.Get().GetLocalizedString("QuarantineDialog_Restore_Failed_Title"),
                            Localizer.Get().GetLocalizedString("QuarantineDialog_Restore_Failed_Message"),
                            button);
                    }
                }
                catch (Exception ex)
                {
                    ShowResultTip(
                        Localizer.Get().GetLocalizedString("QuarantineDialog_OperationFailed"),
                        $"{Localizer.Get().GetLocalizedString("QuarantineDialog_RestoreError")}: {ex.Message}",
                        button);
                }
            }
        }

        /// <summary>
        /// 删除按钮点击事件
        /// </summary>
        private async void DeleteButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is QuarantineItem item)
            {
                try
                {
                    this.Hide();
                    // 确认删除
                    ContentDialog confirmDialog = new()
                    {
                        Title = Localizer.Get().GetLocalizedString("QuarantineDialog_Delete_Confirm_Title"),
                        Content = Localizer.Get().GetLocalizedString("QuarantineDialog_Delete_Confirm_Message"),
                        PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Delete"),
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                        DefaultButton = ContentDialogButton.Close,
                        XamlRoot = this.XamlRoot
                    };

                    if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary)
                    {
                        // 从隔离区路径中提取ID
                        if (string.IsNullOrEmpty(item.QuarantinePath))
                        {
                            ShowResultTip(
                                Localizer.Get().GetLocalizedString("QuarantineDialog_OperationFailed"),
                                Localizer.Get().GetLocalizedString("QuarantineDialog_InvalidPath"),
                                button);
                            return;
                        }

                        string fileName = Path.GetFileName(item.QuarantinePath);
                        if (string.IsNullOrEmpty(fileName))
                        {
                            ShowResultTip(
                                Localizer.Get().GetLocalizedString("QuarantineDialog_OperationFailed"),
                                Localizer.Get().GetLocalizedString("QuarantineDialog_InvalidPath"),
                                button);
                            return;
                        }

                        string[] pathParts = fileName.Split('_');
                        if (pathParts.Length == 0)
                        {
                            ShowResultTip(
                                Localizer.Get().GetLocalizedString("QuarantineDialog_OperationFailed"),
                                Localizer.Get().GetLocalizedString("QuarantineDialog_InvalidPath"),
                                button);
                            return;
                        }

                        string itemId = pathParts[0];

                        // 删除文件
                        bool success = QuarantineManager.DeleteFromQuarantine(itemId);

                        // 刷新列表
                        LoadQuarantineItems();

                        // 显示结果提示
                        if (success)
                        {
                            ShowResultTip(
                                Localizer.Get().GetLocalizedString("QuarantineDialog_Delete_Success_Title"),
                                Localizer.Get().GetLocalizedString("QuarantineDialog_Delete_Success_Message"),
                                button);
                        }
                        else
                        {
                            ShowResultTip(
                                Localizer.Get().GetLocalizedString("QuarantineDialog_Delete_Failed_Title"),
                                Localizer.Get().GetLocalizedString("QuarantineDialog_Delete_Failed_Message"),
                                button);
                        }
                    }
                }
                catch (Exception ex)
                {
                    ShowResultTip(
                        Localizer.Get().GetLocalizedString("QuarantineDialog_OperationFailed"),
                        $"{Localizer.Get().GetLocalizedString("QuarantineDialog_DeleteError")}: {ex.Message}",
                        button);
                }
                finally
                {
                    _ = this.ShowAsync();
                }
            }
        }

        /// <summary>
        /// 清空所有按钮点击事件
        /// </summary>
        private async void ClearAllButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                this.Hide();
                if (_quarantineItems.Count == 0)
                {
                    ShowResultTip(
                        Localizer.Get().GetLocalizedString("QuarantineDialog_Empty_Title"),
                        Localizer.Get().GetLocalizedString("QuarantineDialog_Empty_Message"),
                        ClearAllButton);
                    return;
                }

                // 确认清空
                ContentDialog confirmDialog = new()
                {
                    Title = Localizer.Get().GetLocalizedString("QuarantineDialog_ClearAll_Confirm_Title"),
                    Content = Localizer.Get().GetLocalizedString("QuarantineDialog_ClearAll_Confirm_Message"),
                    PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                    DefaultButton = ContentDialogButton.Close,
                    XamlRoot = this.XamlRoot
                };

                if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary)
                {
                    // 清空隔离区
                    bool success = QuarantineManager.ClearQuarantine();

                    // 刷新列表
                    LoadQuarantineItems();

                    // 显示结果提示
                    if (success)
                    {
                        ShowResultTip(
                            Localizer.Get().GetLocalizedString("QuarantineDialog_ClearAll_Success_Title"),
                            Localizer.Get().GetLocalizedString("QuarantineDialog_ClearAll_Success_Message"),
                            ClearAllButton);
                    }
                    else
                    {
                        ShowResultTip(
                            Localizer.Get().GetLocalizedString("QuarantineDialog_ClearAll_Failed_Title"),
                            Localizer.Get().GetLocalizedString("QuarantineDialog_ClearAll_Failed_Message"),
                            ClearAllButton);
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"清空隔离区失败: {ex.Message}");
                ShowResultTip(
                    Localizer.Get().GetLocalizedString("QuarantineDialog_ClearFailed"),
                    Localizer.Get().GetLocalizedString("QuarantineDialog_ClearFailedMessage"),
                    ClearAllButton);
            }
            finally
            {
                _ = this.ShowAsync();
            }
        }

        /// <summary>
        /// 显示操作结果提示
        /// </summary>
        private void ShowResultTip(string title, string content, FrameworkElement target)
        {
            ResultTeachingTip.Title = title;
            ResultTeachingTip.Subtitle = content;
            ResultTeachingTip.Target = target;
            ResultTeachingTip.IsOpen = true;
        }
    }
}