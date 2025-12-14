using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System.Linq;
using Xdows_Security.ViewModel;

namespace Xdows_Security
{
    public sealed partial class HomePage : Page
    {
        public HomePage()
        {
            InitializeComponent();
            /* 1. ҳ�������ɺ�����ˢ�����ݣ����� UI�� */
            Loaded += async (_, _) => await (DataContext as HomeViewModel)!.LoadOnUiThread();
        }

        /* 2. ��־���ˣ�����ԭ������ */
        private void LogLevelFilter_MenuClick(object sender, RoutedEventArgs e)
        {
            if (sender is not ToggleMenuFlyoutItem item) return;
            var flyout = LogLevelFilter.Flyout as MenuFlyout;
            var selected = flyout!.Items
                                  .OfType<ToggleMenuFlyoutItem>()
                                  .Where(t => t.Tag.ToString() != "All" && t.IsChecked)
                                  .Select(t => t.Tag.ToString()!)
                                  .ToArray();
            (DataContext as HomeViewModel)!.LogLevelFilterCommand.Execute(selected);
        }
    }
}