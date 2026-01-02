using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.WindowsAPICodePack.Dialogs;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using TrustQuarantine;

namespace Xdows_Security
{
    public sealed partial class QuarantineDialog : ContentDialog
    {
        private ObservableCollection<QuarantineItemModel> _items = [];

        public QuarantineDialog()
        {
            InitializeComponent();
            _ = ReloadAsync();
        }

        private Task ReloadAsync()
        {
            _items = new ObservableCollection<QuarantineItemModel>(QuarantineManager.GetQuarantineItems());
            QuarantineListView.ItemsSource = _items;
            return Task.CompletedTask;
        }

        private async void RestoreButton_Click(object sender, RoutedEventArgs e)
            => await RestoreSelectedAsync();

        private async void RestoreMenuItem_Click(object sender, RoutedEventArgs e)
            => await RestoreSelectedAsync();

        private async Task RestoreSelectedAsync()
        {
            var selected = QuarantineListView.SelectedItems.Cast<QuarantineItemModel>().ToList();
            if (selected.Count == 0) return;

            foreach (var item in selected)
            {
                bool ok = await QuarantineManager.RestoreFile(item.FileHash);
                if (ok) _items.Remove(item);
            }

            await ReloadAsync();
        }

        /// <summary>
        /// 单独删除隔离项（不恢复文件）
        /// </summary>
        private async void DeleteMenuItem_Click(object sender, RoutedEventArgs e)
        {
            var selected = QuarantineListView.SelectedItems.Cast<QuarantineItemModel>().ToList();
            if (selected.Count == 0) return;

            // 批量删除持久化
            await QuarantineManager.DeleteItems(selected.Select(x => x.FileHash));

            // 更新 UI
            foreach (var item in selected) _items.Remove(item);
            await ReloadAsync();
        }

        private async void ClearMenuItem_Click(object sender, RoutedEventArgs e)
        {
            await QuarantineManager.ClearQuarantine();
            await ReloadAsync();
        }

        private async void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            await QuarantineManager.ClearQuarantine();
            await ReloadAsync();
        }

        /// <summary>
        /// “添加”：手动把文件塞进隔离区（ThreatName 用简单输入框获取）
        /// </summary>
        private async void AddMenuItem_Click(object sender, RoutedEventArgs e)
            => await AddFromPickerAsync();

        private async void AddButton_Click(object sender, RoutedEventArgs e)
            => await AddFromPickerAsync();

        private async Task AddFromPickerAsync()
        {
            using var dlg = new CommonOpenFileDialog
            {
                Title = "选择要隔离的文件",
                IsFolderPicker = false,
                EnsurePathExists = true,
                Multiselect = false
            };

            if (dlg.ShowDialog() != CommonFileDialogResult.Ok) return;

            string filePath = dlg.FileName;
            if (string.IsNullOrWhiteSpace(filePath)) return;

            // 简单输入 ThreatName
            var tb = new TextBox { PlaceholderText = "威胁名称（可空）" };
            var input = new ContentDialog
            {
                Title = "添加到隔离区",
                Content = tb,
                PrimaryButtonText = "确定",
                CloseButtonText = "取消",
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = this.XamlRoot
            };

            if (await input.ShowAsync() != ContentDialogResult.Primary) return;

            string threatName = tb.Text?.Trim() ?? string.Empty;

            bool ok = await QuarantineManager.AddToQuarantine(filePath, threatName);
            if (ok) await ReloadAsync();
        }
    }
}
