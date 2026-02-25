using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Xdows_Security.Plugins;

namespace Xdows_Security.PluginsLoader
{
    public interface IPlugin
    {
        string Id { get; }
        string Name { get; }
        string Version { get; }
        IconSource? Icon { get; }
        PluginMetadata Metadata { get; }
        void Initialize(object host);
        FrameworkElement? GetView();
    }
}
