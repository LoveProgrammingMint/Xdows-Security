using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PluginFramework
{
    public partial class Plugin
    {
        protected virtual Page Page { get; set; }
        protected virtual ViewModelBase ViewModelBase { get; set; }


        protected virtual void Load()
        {
            // Loading logic for the plugin
            
        }

        protected virtual void Initialize()
        {
            // Initialization logic for the plugin
            ViewModelBase = new ViewModelBase();
        }

        protected virtual Page Entry()
        {
            // Entry point logic for the plugin
            BlankPage Page = new()
            {
                DataContext = ViewModelBase
            };
            return Page;
        }

        protected virtual void Unload()
        {
            // Unloading logic for the plugin

        }

        protected virtual void Exit()
        {
            // Exit logic for the plugin

        }

    }
}
