using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using TrustQuarantine;
using WinUI3Localizer;

namespace Xdows_Security
{
    public sealed partial class QuarantineDialog : ContentDialog
    {
        private ObservableCollection<QuarantineItemModel> _items = [];
        public QuarantineDialog()
        {
            InitializeComponent();
            this.PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Close");// 为了资源复用
            _ = ReloadAsync();
        }
        private Task ReloadAsync()
        {
            _items = new ObservableCollection<QuarantineItemModel>(QuarantineManager.GetQuarantineItems());
            QuarantineListView.ItemsSource = _items;
            return Task.CompletedTask;
        }
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

        private async void DeleteMenuItem_Click(object sender, RoutedEventArgs e)
        {
            var selected = QuarantineListView.SelectedItems.Cast<QuarantineItemModel>().ToList();
            if (selected.Count == 0) return;
            await QuarantineManager.DeleteItems(selected.Select(x => x.FileHash));
            foreach (var item in selected) _items.Remove(item);
            await ReloadAsync();
        }

        private async void ClearMenuItem_Click(object sender, RoutedEventArgs e)
        {
            await QuarantineManager.ClearQuarantine();
            await ReloadAsync();
        }
    }
}
