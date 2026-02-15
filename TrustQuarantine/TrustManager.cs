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
    [JsonSerializable(typeof(TrustItemModel))]
    internal partial class TrustJsonContext : JsonSerializerContext { }

    public static class TrustManager
    {
        private static string TrustFolderPath => Path.Combine(ApplicationData.LocalFolder.Path, "Trust");

        private static void EnsureTrustFolderExists()
        {
            if (!Directory.Exists(TrustFolderPath))
            {
                Directory.CreateDirectory(TrustFolderPath);
            }
        }

        public static List<TrustItemModel> GetTrustItems()
        {
            var trustItems = new List<TrustItemModel>();
            EnsureTrustFolderExists();

            foreach (var file in Directory.GetFiles(TrustFolderPath))
            {
                try
                {
                    string json = File.ReadAllText(file);
                    var item = JsonSerializer.Deserialize(json, TrustJsonContext.Default.TrustItemModel);
                    if (item != null && !string.IsNullOrEmpty(item.SourcePath))
                    {
                        trustItems.Add(item);
                    }
                }
                catch
                {
                    // 忽略解析错误
                }
            }

            return trustItems;
        }

        public static async Task<bool> AddToTrust(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                return false;

            try
            {
                string fileHash = await CalculateFileHashAsync(filePath);

                var currentItems = GetTrustItems();
                if (currentItems.Any(item => string.Equals(item.Hash, fileHash, StringComparison.OrdinalIgnoreCase)))
                    return true; // 文件已存在

                var item = new TrustItemModel
                {
                    SourcePath = filePath,
                    Hash = fileHash
                };

                string trustItemFilePath = Path.Combine(TrustFolderPath, $"{fileHash}.json");
                string json = JsonSerializer.Serialize(item, TrustJsonContext.Default.TrustItemModel);
                await File.WriteAllTextAsync(trustItemFilePath, json);

                return true;
            }
            catch
            {
                return false;
            }
        }

        public static async Task<bool> AddToTrustByHash(string filePath, string fileHash)
        {
            if (string.IsNullOrWhiteSpace(fileHash))
                return false;

            try
            {
                var currentItems = GetTrustItems();
                if (currentItems.Any(item => string.Equals(item.Hash, fileHash, StringComparison.OrdinalIgnoreCase)))
                    return true; // 已存在

                var item = new TrustItemModel
                {
                    SourcePath = filePath ?? string.Empty,
                    Hash = fileHash
                };

                string trustItemFilePath = Path.Combine(TrustFolderPath, $"{fileHash}.json");
                string json = JsonSerializer.Serialize(item, TrustJsonContext.Default.TrustItemModel);
                await File.WriteAllTextAsync(trustItemFilePath, json);

                return true;
            }
            catch
            {
                return false;
            }
        }

        public static async Task<bool> RemoveFromTrust(string filePath)
        {
            var currentItems = GetTrustItems();
            var itemToRemove = currentItems.FirstOrDefault(item => item.SourcePath == filePath);

            if (itemToRemove == null)
                return false;

            string trustItemFilePath = Path.Combine(TrustFolderPath, $"{itemToRemove.Hash}.json");
            if (File.Exists(trustItemFilePath))
            {
                File.Delete(trustItemFilePath);
                return true;
            }
            return false;
        }

        public static async Task<bool> ClearTrust()
        {
            if (Directory.Exists(TrustFolderPath))
            {
                foreach (var file in Directory.GetFiles(TrustFolderPath))
                {
                    File.Delete(file);
                }
            }
            return true;
        }

        public static bool IsPathTrusted(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                return false;

            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hashBytes = sha256.ComputeHash(stream);
                string hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();

                var trustItems = GetTrustItems();
                return trustItems.Any(item => string.Equals(item.Hash, hash, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }

        private static async Task<string> CalculateFileHashAsync(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hashBytes = await sha256.ComputeHashAsync(stream);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }
    }
}
