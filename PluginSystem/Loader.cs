using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace PluginSystem
{
    
    public class Config
    {
        [JsonPropertyName("Name")]
        public string Name { get; set; }

        [JsonPropertyName("NameSpase")]
        public string NameSpase { get; set; }

        [JsonPropertyName("EntryAddress")]
        public string EntryAddress { get; set; }

        [JsonPropertyName("EntryFunction")]
        public string EntryFunction { get; set; }
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
            Type t = asm.GetType(config.EntryAddress);

            object obj = Activator.CreateInstance(t);

            MethodInfo mi = t.GetMethod(config.EntryFunction);
            return (Page)mi.Invoke(obj, []);
        }

        public Assembly Load(string Name)
        {
            if (!File.Exists($".\\Plugin\\{Name}\\Plugin.dll")) state = LoadState.Borken;

            try
            {
                Assembly asm = Assembly.LoadFrom($".\\Plugin\\{Name}\\Plugin.dll");
                return asm;
            }
            catch (Exception)
            {
                state = LoadState.Borken;
            }
            return null;
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
            catch (Exception)
            {
                state = LoadState.Borken;
            }
        }
    }
}
