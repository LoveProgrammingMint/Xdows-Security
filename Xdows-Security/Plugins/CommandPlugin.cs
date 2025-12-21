using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Xdows_Security.Plugins;
using Xdows_Security.Views;

namespace Xdows_Security.Plugins
{
    public class CommandPlugin : IPlugin
    {
        public string Id => "builtin.commandprompt";
        public string Name => "命令提示符";
        public string Version => "1.0.0";
        public IconSource Icon => new FontIconSource
        {
            Glyph = "\uE756"
        }; 
        public PluginMetadata Metadata => new PluginMetadata
        {
            Id = Id,
            Name = Name,
            Description = "Built-in command prompt plugin",
            Author = "Xdows Software",
            Version = Version
        };

        private CommandPromptView? _view;

        public void Initialize(object host) { }

        public FrameworkElement? GetView()
        {
            _view ??= new CommandPromptView();
            return _view;
        }
    }
}
