using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Xdows_Security.Plugins
{
    public class PopupPlugin : IPlugin
    {
        public string Id => "builtin.popup";
        public string Name => "弹窗拦截器";
        public string Version => "1.0.0";
        public IconSource Icon => new FontIconSource
        {
            Glyph = "\uEA0D"
        }; public PluginMetadata Metadata => new()
        {
            Id = Id,
            Name = Name,
            Description = "Built-in popup plugin",
            Author = "Xdows Software",
            Version = Version
        };
        private Xdows_Security.Views.PopupBlockerView? _view;

        public void Initialize(object host)
        {
        }

        public FrameworkElement? GetView()
        {
            _view ??= new Xdows_Security.Views.PopupBlockerView();
            return _view;
        }
    }
}
