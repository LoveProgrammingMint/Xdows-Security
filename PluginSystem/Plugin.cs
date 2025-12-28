using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

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
        public static string[] GetPluginsList()
        {
            string pluginBaseDir = @".\Plugin";
            var validFolderNames = new List<string>();

            if (!Directory.Exists(pluginBaseDir))
                return [.. validFolderNames];

            foreach (string folderPath in Directory.GetDirectories(pluginBaseDir))
            {
                string folderName = Path.GetFileName(folderPath);
                string dllPath = Path.Combine(folderPath, "PluginFramework.dll");
                string jsonPath = Path.Combine(folderPath, "Information.json");

                if (File.Exists(dllPath) && File.Exists(jsonPath))
                {
                    validFolderNames.Add(folderName);
                }
            }

            return [.. validFolderNames];
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
