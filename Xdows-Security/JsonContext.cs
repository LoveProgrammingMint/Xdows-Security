using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Xdows_Security
{
    [JsonSourceGenerationOptions(
        PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultBufferSize = 4096)]
    [JsonSerializable(typeof(Dictionary<string, object>))]
    internal partial class JsonContext : JsonSerializerContext
    {
    }
}
