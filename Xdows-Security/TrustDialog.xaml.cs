using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.WindowsAPICodePack.Dialogs;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using TrustQuarantine;
using WinUI3Localizer;

namespace Xdows_Security
{
    public sealed partial class TrustDialog : ContentDialog
    {
        private ObservableCollection<TrustItemModel> _trustItems = [];
        public TrustDialog()
        {
            this.InitializeComponent();
            this.PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Close");// 为了资源复用
            _ = InitializeTrustList();
        }
        private async Task InitializeTrustList()
        {
            var trustItems = TrustManager.GetTrustItems();
            _trustItems = new ObservableCollection<TrustItemModel>(trustItems);
            TrustListView.ItemsSource = _trustItems;
        }
        private async void DeleteMenuItem_Click(object sender, RoutedEventArgs e)
        {
            var selectedItems = TrustListView.SelectedItems.Cast<TrustItemModel>().ToList();

            foreach (var item in selectedItems)
            {
                bool success = await TrustManager.RemoveFromTrust(item.Path);
                if (success)
                {
                    _trustItems.Remove(item);
                }
            }
            await InitializeTrustList();
        }
        private async void ClearMenuItem_Click(object sender, RoutedEventArgs e)
        {
            bool success = await TrustManager.ClearTrust();
            if (success)
            {
                await InitializeTrustList();
            }
        }
        private async void AddMenuItem_Click(object sender, RoutedEventArgs e)
        {
            using var dlg = new CommonOpenFileDialog
            {
                Title = Localizer.Get().GetLocalizedString("TrustDialog_SelectFile_Title"),
                IsFolderPicker = false,
                EnsurePathExists = true,
            };
            if (dlg.ShowDialog() == CommonFileDialogResult.Ok)
            {
                var filePath = dlg.FileName;

                if (!string.IsNullOrEmpty(filePath))
                {
                    bool success = await TrustManager.AddToTrust(filePath);
                    if (success)
                    {
                        await InitializeTrustList();
                    }
                }
            }
        }
    }
}
