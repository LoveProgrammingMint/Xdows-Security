namespace Xdows_Security.Model
{
    public class PluginItem
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string ShortName { get; set; } = string.Empty;
        public PluginSystem.PSystem.Plugin? SourcePlugin { get; set; }
    }
}
