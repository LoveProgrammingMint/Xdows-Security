using Microsoft.UI.Xaml.Controls;
using System.Linq;
using System.Collections.Generic;
using Xdows_Security.Services;
using Xdows_Security.PluginsLoader;

namespace Xdows_Security.Views
{
    public sealed partial class XdowsToolsPage : Page
    {
        public XdowsToolsPage()
        {
            InitializeComponent();
        }
        private async void Page_Loaded(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {
            try
            {
                PluginLoader loader = new();
                List<IPlugin> plugins = [.. loader.LoadPlugins(this)];
                foreach (IPlugin plugin in plugins)
                {
                    try
                    {
                        TabViewItem tab = new()
                        {
                            Header = new TextBlock
                            {
                                Text = plugin.Name ?? plugin.Metadata?.Name ?? plugin.Id,
                                FontSize = 14
                            },
                            IconSource = plugin.Icon,
                            IsClosable = false,
                            Content = plugin.GetView() ?? new TextBlock { Text = WinUI3Localizer.Localizer.Get().GetLocalizedString("AllPage_Undefined") }
                        };
                        TabView.TabItems.Add(tab);
                    }
                    catch { }
                }
            }
            catch { }
        }
    }
}