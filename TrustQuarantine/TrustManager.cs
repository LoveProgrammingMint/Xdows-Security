using Compatibility.Windows.Storage;
using System.Security.Cryptography;

namespace TrustQuarantine
{
    public static class TrustManager
    {
        private static readonly string TrustDataKey = "TrustData";

        // 获取所有信任项
        public static List<TrustItemModel> GetTrustItems()
        {
            var trustItems = new List<TrustItemModel>();

            if (ApplicationData.Current.LocalSettings.Values[TrustDataKey] is List<Dictionary<string, string>> savedData)
            {
                foreach (var item in savedData)
                {
                    if (item.TryGetValue("Path", out string? value) && item.TryGetValue("Hash", out string? value1))
                    {
                        trustItems.Add(new TrustItemModel(value, value1));
                    }
                }
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
            var trustItems = GetTrustItems();
            return trustItems.Any(item => item.Path.Equals(path, StringComparison.OrdinalIgnoreCase));
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
            var itemsToSave = trustItems.Select(item => new Dictionary<string, string>
            {
                { "Path", item.Path },
                { "Hash", item.Hash }
            }).ToList();

            ApplicationData.Current.LocalSettings.Values[TrustDataKey] = itemsToSave;
        }
    }
}
