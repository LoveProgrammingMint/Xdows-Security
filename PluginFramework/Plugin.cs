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
        public virtual Page Page { get; set; }
        public virtual ViewModelBase ViewModelBase { get; set; }


        public virtual void Load()
        {
            // Loading logic for the plugin
            
        }

        public virtual void Initialize()
        {
            // Initialization logic for the plugin
            ViewModelBase = new ViewModelBase();
        }

        public virtual Page Entry()
        {
            // Entry point logic for the plugin
            Initialize();
            //BlankPage Page = new()
            //{
            //    DataContext = ViewModelBase
            //};
            return new();
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
