using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.UI.Xaml;
using Xdows_Security.Plugins;

namespace Xdows_Security.Services
{
    public class PluginLoader
    {
        public string PluginDirectory { get; }

        public PluginLoader(string? pluginDirectory = null)
        {
            PluginDirectory = pluginDirectory ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Plugins");
            if (!Directory.Exists(PluginDirectory)) Directory.CreateDirectory(PluginDirectory);
        }

        public IEnumerable<IPlugin> LoadPlugins(object? host = null)
        {
            var list = new List<IPlugin>();
            try
            {
                // Discover built-in plugins from already loaded assemblies
                try
                {
                    var loaded = AppDomain.CurrentDomain.GetAssemblies();
                    foreach (var asm in loaded)
                    {
                        try
                        {
                            var types = asm.GetTypes().Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsAbstract);
                            foreach (var t in types)
                            {
                                try
                                {
                                    if (Activator.CreateInstance(t) is IPlugin plugin)
                                    {
                                        plugin.Initialize(host ?? Application.Current);
                                        list.Add(plugin);
                                    }
                                }
                                catch { }
                            }
                        }
                        catch { }
                    }
                }
                catch { }

                // Discover external plugin DLLs in Plugins folder
                var dlls = Directory.GetFiles(PluginDirectory, "*.dll", SearchOption.TopDirectoryOnly);
                foreach (var dll in dlls)
                {
                    try
                    {
                        var asm = Assembly.LoadFrom(dll);
                        var types = asm.GetTypes().Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsAbstract);
                        foreach (var t in types)
                        {
                            try
                            {
                                if (Activator.CreateInstance(t) is IPlugin plugin)
                                {
                                    plugin.Initialize(host ?? Application.Current);
                                    list.Add(plugin);
                                }
                            }
                            catch { /* individual plugin init failed */ }
                        }
                    }
                    catch { /* assembly load failed */ }
                }
            }
            catch { }
            return list;
        }
    }
}
