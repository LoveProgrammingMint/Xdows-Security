namespace Xdows_Security.Plugins
{
    public record PluginMetadata
    {
        public string Id { get; init; } = string.Empty;
        public string Name { get; init; } = string.Empty;
        public string Description { get; init; } = string.Empty;
        public string Author { get; init; } = string.Empty;
        public string Version { get; init; } = "1.0.0";
        public string Requires { get; init; } = string.Empty; // e.g. "admin"
    }
}
