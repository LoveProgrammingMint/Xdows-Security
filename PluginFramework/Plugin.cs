using Microsoft.UI.Xaml.Controls;

namespace PluginFramework
{
    public partial class Plugin
    {
        public virtual ViewModelBase ViewModelBase { get; set; }

        public virtual void Load()
        {
            // Loading logic for the plugin
        }

        public virtual void Initialize()
        {

        }

        public virtual Page Entry()
        {
            Initialize();
            Page page = new();
            Grid grid = new()
            {
                DataContext = new TextBlock
                {
                    Text = "Hello from Plugin Framework!"
                }
            };
            page.Content = grid;

            return page;
        }

        public virtual void Unload()
        {
            // Unloading logic for the plugin
        }

        public virtual void Exit()
        {
            // Exit logic for the plugin
        }

    }
}
