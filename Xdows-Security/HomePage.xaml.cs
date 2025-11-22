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
            /* 1. 页面加载完成后立即刷新数据（不堵 UI） */
            Loaded += (_, _) => (DataContext as HomeViewModel)!.LoadOnUiThread();
        }

        /* 2. 日志过滤（保持原交互） */
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