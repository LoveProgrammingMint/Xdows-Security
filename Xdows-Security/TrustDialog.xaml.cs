using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using WinUI3Localizer;
using Xdows.Protection;

namespace Xdows_Security
{
    public sealed partial class TrustDialog : ContentDialog
    {
        private readonly ObservableCollection<TrustItemViewModel> _trustItems = new ObservableCollection<TrustItemViewModel>();
        public new string Title => Localizer.Get().GetLocalizedString("TrustDialog_Title");
        public new string CloseButtonText => Localizer.Get().GetLocalizedString("TrustDialog_CloseButton");

        public TrustDialog()
        {
            this.InitializeComponent();
            InitializeTrustList();
        }

        /// <summary>
        /// 初始化信任列表
        /// </summary>
        private void InitializeTrustList()
        {
            LoadTrustItems();
            TrustListView.ItemsSource = _trustItems;
            UpdateStatusText();
        }

        /// <summary>
        /// 加载信任项
        /// </summary>
        private void LoadTrustItems()
        {
            _trustItems.Clear();

            var trustItems = TrustManager.GetTrustItems();
            foreach (var item in trustItems)
            {
                _trustItems.Add(new TrustItemViewModel(item));
            }
        }

        /// <summary>
        /// 更新状态文本
        /// </summary>
        private void UpdateStatusText()
        {
            if (_trustItems.Count == 0)
            {
                StatusText.Text = Localizer.Get().GetLocalizedString("TrustDialog_EmptyStatus");
            }
            else
            {
                StatusText.Text = Localizer.Get().GetLocalizedString("TrustDialog_TotalCount").Replace("{0}", _trustItems.Count.ToString());
            }
        }

        /// <summary>
        /// 显示操作结果提示
        /// </summary>
        private void ShowResultTip(string title, bool isSuccess)
        {
            ResultTeachingTip.Title = title;
            ResultTeachingTip.Subtitle = isSuccess ?
                Localizer.Get().GetLocalizedString("Common_OperationSuccess") :
                Localizer.Get().GetLocalizedString("Common_OperationFailed");
            ResultTeachingTip.IsOpen = true;
        }

        /// <summary>
        /// 添加按钮点击事件
        /// </summary>
        private async void AddButton_Click(object sender, RoutedEventArgs e)
        {
            this.Hide();
            var addDialog = new AddTrustDialog
            {
                XamlRoot = this.XamlRoot
            };

            await addDialog.ShowAsync();
            // 重新显示当前对话框并刷新列表
            LoadTrustItems();
            UpdateStatusText();
            await this.ShowAsync();
        }

        /// <summary>
        /// 清空按钮点击事件
        /// </summary>
        private async void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            if (_trustItems.Count == 0)
            {
                ShowResultTip(Localizer.Get().GetLocalizedString("TrustDialog_EmptyTitle"), false);
                return;
            }

            // 先关闭当前对话框
            this.Hide();

            var confirmDialog = new ContentDialog
            {
                Title = Localizer.Get().GetLocalizedString("TrustDialog_ConfirmClearTitle"),
                Content = $"{Localizer.Get().GetLocalizedString("TrustDialog_ConfirmClearContent")} {_trustItems.Count} {Localizer.Get().GetLocalizedString("TrustDialog_ConfirmClearItems")}",
                PrimaryButtonText = Localizer.Get().GetLocalizedString("TrustDialog_ClearAll"),
                CloseButtonText = Localizer.Get().GetLocalizedString("Common_Cancel"),
                DefaultButton = ContentDialogButton.Close,
                XamlRoot = this.XamlRoot
            };

            if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary)
            {
                bool success = TrustManager.ClearTrust();

                // 刷新列表
                LoadTrustItems();
                UpdateStatusText();

                // 使用非阻塞提示而不是嵌套对话框
                if (success)
                {
                    ShowResultTip(Localizer.Get().GetLocalizedString("TrustDialog_ClearSuccessTitle"), true);
                }
                else
                {
                    ShowResultTip(Localizer.Get().GetLocalizedString("TrustDialog_ClearFailedTitle"), false);
                }
            }

            // 重新显示当前对话框
            await this.ShowAsync();
        }

        /// <summary>
        /// 移除按钮点击事件
        /// </summary>
        private async void RemoveButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string id)
            {
                var item = _trustItems.FirstOrDefault(t => t.Id == id);
                if (item == null) return;

                // 先关闭当前对话框
                this.Hide();

                var confirmDialog = new ContentDialog
                {
                    Title = Localizer.Get().GetLocalizedString("TrustDialog_ConfirmRemoveTitle"),
                    Content = $"{Localizer.Get().GetLocalizedString("TrustDialog_ConfirmRemoveContent")} \"{item.Name}\" {Localizer.Get().GetLocalizedString("TrustDialog_ConfirmRemoveSuffix")}",
                    PrimaryButtonText = Localizer.Get().GetLocalizedString("TrustDialog_Remove"),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Common_Cancel"),
                    DefaultButton = ContentDialogButton.Close,
                    XamlRoot = this.XamlRoot
                };

                if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary)
                {
                    bool success = TrustManager.RemoveFromTrust(id);

                    // 刷新列表
                    LoadTrustItems();
                    UpdateStatusText();

                    // 使用非阻塞提示而不是嵌套对话框
                    if (success)
                    {
                        ShowResultTip(Localizer.Get().GetLocalizedString("TrustDialog_RemoveSuccessTitle"), true);
                    }
                    else
                    {
                        ShowResultTip(Localizer.Get().GetLocalizedString("TrustDialog_RemoveFailedTitle"), false);
                    }
                }

                // 重新显示当前对话框
                await this.ShowAsync();
            }
        }
    }

    /// <summary>
    /// 信任项视图模型
    /// </summary>
    public record TrustItemViewModel
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Path { get; set; }
        public string Type { get; set; }
        public string TypeIcon { get; set; }
        public string FormattedAddedDate { get; set; }

        public TrustItemViewModel(TrustItem item)
        {
            Id = item.Id;
            Name = item.Name;
            Path = item.Path;
            Type = item.Type == TrustItemType.File ? Localizer.Get().GetLocalizedString("TrustItem_Type_File") : Localizer.Get().GetLocalizedString("TrustItem_Type_Folder");
            TypeIcon = item.Type == TrustItemType.File ? "\uE8A5" : "\uE8B7"; // 文件图标和文件夹图标
            FormattedAddedDate = item.FormattedAddedDate;
        }
    }
}