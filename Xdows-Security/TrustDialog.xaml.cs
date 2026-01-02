using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.WindowsAPICodePack.Dialogs;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using TrustQuarantine;

namespace Xdows_Security
{
    public sealed partial class TrustDialog : ContentDialog
    {
        private ObservableCollection<TrustItemModel> _trustItems = new ObservableCollection<TrustItemModel>();

        public TrustDialog()
        {
            this.InitializeComponent();
            _ = InitializeTrustList();
        }

        // 初始化信任列表
        private async Task InitializeTrustList()
        {
            // 获取并更新信任项
            var trustItems = TrustManager.GetTrustItems();
            _trustItems = new ObservableCollection<TrustItemModel>(trustItems);
            TrustListView.ItemsSource = _trustItems;
        }

        // 添加信任项
        private async void AddButton_Click(object sender, RoutedEventArgs e)
        {
            using var dlg = new CommonOpenFileDialog
            {
                Title = "选择文件",
                IsFolderPicker = false,
                EnsurePathExists = true,
            };

            // 用户选择文件后
            if (dlg.ShowDialog() == CommonFileDialogResult.Ok)
            {
                var filePath = dlg.FileName;

                if (!string.IsNullOrEmpty(filePath))
                {
                    // 添加信任项并更新列表
                    bool success = await TrustManager.AddToTrust(filePath);
                    if (success)
                    {
                        await InitializeTrustList(); // 刷新信任列表
                    }
                }
            }
        }

        // 移除信任项
        private async void RemoveButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string filePath)
            {
                bool success = await TrustManager.RemoveFromTrust(filePath);
                if (success)
                {
                    await InitializeTrustList(); // 刷新信任列表
                }
            }
        }

        // 清空信任区
        private async void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            bool success = await TrustManager.ClearTrust();
            if (success)
            {
                await InitializeTrustList(); // 刷新信任列表
            }
        }
    }
}
