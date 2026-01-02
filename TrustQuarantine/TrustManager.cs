using Compatibility.Windows.Storage;
using System.Security.Cryptography;
using System.Text.Json;

namespace TrustQuarantine
{
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
                    var savedData = JsonSerializer.Deserialize<List<Dictionary<string, string>>>(savedDataJson);
                    if (savedData != null)
                    {
                        foreach (var item in savedData)
                        {
                            if (item.TryGetValue("Path", out string? path) && item.TryGetValue("Hash", out string? hash))
                            {
                                trustItems.Add(new TrustItemModel(path, hash));
                            }
                        }
                    }
                }
                catch { }
            }

            return trustItems;
        }

        // 添加文件到信任区
        public static async Task<bool> AddToTrust(string path)
        {
            if (!File.Exists(path)) return false;

            string fileHash = await GetFileHashAsync(path);

            var trustItem = new TrustItemModel(path, fileHash);

            var currentItems = GetTrustItems();
            if (currentItems.Any(item => item.Hash == fileHash)) return true; // 文件已存在

            currentItems.Add(trustItem);

            // 保存到本地设置
            await SaveTrustItemsAsync(currentItems);

            return true;
        }

        // 移除信任项
        public static async Task<bool> RemoveFromTrust(string path)
        {
            var currentItems = GetTrustItems();
            var itemToRemove = currentItems.FirstOrDefault(item => item.Path == path);

            if (itemToRemove == null) return false;

            currentItems.Remove(itemToRemove);

            // 保存更新后的信任项
            await SaveTrustItemsAsync(currentItems);

            return true;
        }

        public static bool IsPathTrusted(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return false;
            string hash;
            using (var sha256 = SHA256.Create())
            using (var stream = File.OpenRead(path))
            {
                var hashBytes = sha256.ComputeHash(stream);
                hash = Convert.ToHexStringLower(hashBytes);
            }
            var trustItems = GetTrustItems();
            return trustItems.Any(item =>
                string.Equals(item.Hash, hash, StringComparison.OrdinalIgnoreCase));
        }

        // 清空信任区
        public static async Task<bool> ClearTrust()
        {
            await SaveTrustItemsAsync(new List<TrustItemModel>());
            return true;
        }

        // 获取文件的哈希值
        private static async Task<string> GetFileHashAsync(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hashBytes = await sha256.ComputeHashAsync(stream);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }

        // 保存信任项到本地存储
        private static async Task SaveTrustItemsAsync(List<TrustItemModel> trustItems)
        {
            // 将信任项序列化为 JSON 字符串
            var itemsToSave = trustItems.Select(item => new Dictionary<string, string>
            {
                { "Path", item.Path },
                { "Hash", item.Hash }
            }).ToList();

            string jsonString = JsonSerializer.Serialize(itemsToSave);

            // 将序列化后的 JSON 字符串保存到本地设置
            ApplicationData.Current.LocalSettings.Values[TrustDataKey] = jsonString;
        }
    }
}
