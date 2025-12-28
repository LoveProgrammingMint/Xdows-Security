using Microsoft.UI.Xaml.Controls;
using System;
using System.IO;
using System.Reflection;
using System.Text.Json;

namespace PluginSystem
{

    public class Config
    {
        public string Name { get; set; }
        public string NameSpase { get; set; }
        public string EntryAddress { get; set; }
        public string EntryFunction { get; set; }
        public string Description { get; set; }
    }
    public enum LoadState
    {
        None,
        NotFound,
        Borken
    }

    internal class Loader
    {
        public Config config;
        public LoadState state;
        public Type type;

        public Page GetGrid(Assembly asm)
        {
            try
            {
                Type t = asm.GetType(config.EntryAddress);

                object obj = Activator.CreateInstance(t);

                MethodInfo mi = t.GetMethod(config.EntryFunction);
                return (Page)mi.Invoke(obj, []);
            }
            catch
            {
                return new Page();
            }
        }

        public Assembly Load(string Name)
        {
            if (!File.Exists($".\\Plugin\\{Name}\\PluginFramework.dll")) state = LoadState.Borken;

            try
            {
                Assembly asm = Assembly.LoadFrom($".\\Plugin\\{Name}\\PluginFramework.dll");
                return asm;
            }
            catch (Exception)
            {
                state = LoadState.Borken;
                throw;
            }
        }
        public void LoadConfig(string Name)
        {
            if (string.IsNullOrEmpty(Name)) state = LoadState.NotFound;

            if (!File.Exists($".\\Plugin\\{Name}")) state = LoadState.NotFound;
            try
            {
                string json = File.ReadAllText($".\\Plugin\\{Name}\\Information.json");
                config = JsonSerializer.Deserialize<Config>(json);
            }
            catch { }
        }
    }
}
