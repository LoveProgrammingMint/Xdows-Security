using Compatibility.Windows.Storage;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TrustQuarantine
{
    [JsonSourceGenerationOptions(
        WriteIndented = false,
        PropertyNameCaseInsensitive = true
    )]
    [JsonSerializable(typeof(List<Dictionary<string, string>>))]
    internal partial class TrustJsonContext : JsonSerializerContext { }

    public static class TrustManager
    {
        private static readonly string TrustDataKey = "TrustData";

        public static List<TrustItemModel> GetTrustItems()
        {
            var trustItems = new List<TrustItemModel>();

            if (ApplicationData.Current.LocalSettings.Values[TrustDataKey] is string savedDataJson)
            {
                try
                {
                    var savedData = JsonSerializer.Deserialize(
                        savedDataJson,
                        TrustJsonContext.Default.ListDictionaryStringString
                    );

                    if (savedData != null)
                    {
                        foreach (var item in savedData)
                        {
                            if (item.TryGetValue("Path", out string? path) &&
                                item.TryGetValue("Hash", out string? hash))
                            {
                                trustItems.Add(new TrustItemModel(path, hash));
                            }
                        }
                    }
                }
                catch
                {
                    // 忽略解析错误
                }
            }

            return trustItems;
        }

        // 添加文件到信任区
        public static async Task<bool> AddToTrust(string path)
        {
            if (!File.Exists(path))
                return false;

            string fileHash = await GetFileHashAsync(path);

            var currentItems = GetTrustItems();
            if (currentItems.Any(item => item.Hash == fileHash))
                return true; // 文件已存在

            currentItems.Add(new TrustItemModel(path, fileHash));
            await SaveTrustItemsAsync(currentItems);
            return true;
        }

        // 移除信任项
        public static async Task<bool> RemoveFromTrust(string path)
        {
            var currentItems = GetTrustItems();
            var itemToRemove = currentItems.FirstOrDefault(item => item.Path == path);

            if (itemToRemove == null)
                return false;

            currentItems.Remove(itemToRemove);
            await SaveTrustItemsAsync(currentItems);
            return true;
        }

        public static bool IsPathTrusted(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return false;

            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(path);
                var hashBytes = sha256.ComputeHash(stream);
                string hash = Convert.ToHexString(hashBytes).ToLowerInvariant();

                var trustItems = GetTrustItems();
                return trustItems.Any(item =>
                    string.Equals(item.Hash, hash, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false; // 文件访问失败视为不信任
            }
        }

        // 清空信任区
        public static async Task<bool> ClearTrust()
        {
            await SaveTrustItemsAsync(new List<TrustItemModel>());
            return true;
        }

        // 通过已知哈希值直接添加信任项
        public static async Task<bool> AddToTrustByHash(string path, string hash)
        {
            if (string.IsNullOrWhiteSpace(hash))
                return false;

            var currentItems = GetTrustItems();
            if (currentItems.Any(item =>
                string.Equals(item.Hash, hash, StringComparison.OrdinalIgnoreCase)))
                return true; // 已存在

            currentItems.Add(new TrustItemModel(path ?? string.Empty, hash));
            await SaveTrustItemsAsync(currentItems);
            return true;
        }

        // 获取文件的哈希值
        private static async Task<string> GetFileHashAsync(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hashBytes = await sha256.ComputeHashAsync(stream);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }

        // 保存信任项到本地存储
        private static async Task SaveTrustItemsAsync(List<TrustItemModel> trustItems)
        {
            var itemsToSave = trustItems.Select(item => new Dictionary<string, string>
            {
                { "Path", item.Path },
                { "Hash", item.Hash }
            }).ToList();
            string jsonString = JsonSerializer.Serialize(
                itemsToSave,
                TrustJsonContext.Default.ListDictionaryStringString
            );

            ApplicationData.Current.LocalSettings.Values[TrustDataKey] = jsonString;
        }
    }
}