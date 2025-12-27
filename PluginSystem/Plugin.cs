using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace PluginSystem
{
    public partial class PSystem
    {
        private readonly List<Plugin> Plugins = [];
        public LoadState LoadPlugin(string PluginName)
        {
            Loader loader = new();
            loader.LoadConfig(PluginName);
            var asm = loader.Load(PluginName);
            if (asm == null) return loader.state;
            Plugin plugin = new()
            {
                Assembly = asm,
                Config = loader.config,
                Name = PluginName,
                Type = loader.type,
                PluginPage = loader.GetGrid(asm)
            };
            Plugins.Add(plugin);
            return loader.state;
        }

        public List<Plugin> GetPlugins()
        {
            return Plugins;
        }

        public Plugin GetPlugin(string Name)
        {
            foreach (Plugin p in Plugins)
            {
                if (p.Name == Name) return p;
            }
            return null;
        }

        public void UnloadPlugin(string Name)
        {
            Plugin plugin = GetPlugin(Name);
            if (plugin != null)
            {
                Plugins.Remove(plugin);
            }

        }

        public class Plugin
        {
            public Config Config { get; set; }
            public Assembly Assembly { get; set; }
            public string Name { get; set; }
            public Type Type { get; set; }
            public Page PluginPage { get; set; }
            
        }
    }
}
