using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.Storage.Pickers;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using TrustQuarantine;
using WinUI3Localizer;

namespace Xdows_Security
{
    public sealed partial class TrustDialog : ContentDialog
    {
        private ObservableCollection<TrustItemModel> _items = [];

        public TrustDialog()
        {
            this.InitializeComponent();
            this.PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Close");// 为了资源复用 By Shiyi
            _ = ReloadAsync();
        }

        private Task ReloadAsync()
        {
            try
            {
                var items = TrustManager.GetTrustItems();
                if (items != null)
                {
                    _items = new ObservableCollection<TrustItemModel>(items);
                    TrustListView.ItemsSource = _items;
                }
            }
            catch
            {
                // 忽略加载错误
            }
            return Task.CompletedTask;
        }

        private async void DeleteMenuItem_Click(object sender, RoutedEventArgs e)
        {
            var selectedItems = TrustListView.SelectedItems.Cast<TrustItemModel>().ToList();
            if (selectedItems.Count == 0) return;

            foreach (var item in selectedItems)
            {
                await TrustManager.RemoveFromTrust(item.SourcePath);
                _items.Remove(item);
            }

            await ReloadAsync();
        }

        private async void ClearMenuItem_Click(object sender, RoutedEventArgs e)
        {
            await TrustManager.ClearTrust();
            await ReloadAsync();
        }

        private async void AddMenuItem_Click(object sender, RoutedEventArgs e)
        {
            PickFileResult file = await (new FileOpenPicker(XamlRoot.ContentIslandEnvironment.AppWindowId).PickSingleFileAsync());
            if (file is null) { return; }
            await TrustManager.AddToTrust(file.Path);
            _ = ReloadAsync();
        }
    }
}
