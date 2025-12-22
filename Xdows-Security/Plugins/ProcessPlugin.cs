using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Xdows_Security.Views;

namespace Xdows_Security.Plugins
{
    public class ProcessPlugin : IPlugin
    {
        public string Id => "builtin.process";

        public string Name => "进程管理器";

        public string Version => "1.0.0";
        public IconSource Icon => new FontIconSource
        {
            Glyph = "\uE9D9"
        };
        public PluginMetadata Metadata => new()
        {
            Id = Id,
            Name = Name,
            Description = "Built-in process manager plugin",
            Author = "Xdows Software",
            Version = Version
        };

        private ProcessManagerView? _view;

        public void Initialize(object host)
        {
            // host can be used to access app services if needed
        }

        public FrameworkElement? GetView()
        {
            _view ??= new ProcessManagerView();
            return _view;
        }
    }
}
