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
    [JsonSerializable(typeof(QuarantineItemModel))]
    internal partial class QuarantineJsonContext : JsonSerializerContext { }

    public static class QuarantineManager
    {
        private static string QuarantineFolderPath => Path.Combine(ApplicationData.LocalFolder.Path, "Quarantine");

        private static void EnsureQuarantineFolderExists()
        {
            if (!Directory.Exists(QuarantineFolderPath))
            {
                Directory.CreateDirectory(QuarantineFolderPath);
            }
        }

        public static List<QuarantineItemModel> GetQuarantineItems()
        {
            var quarantineItems = new List<QuarantineItemModel>();
            EnsureQuarantineFolderExists();

            foreach (var file in Directory.GetFiles(QuarantineFolderPath))
            {
                try
                {
                    string json = File.ReadAllText(file);
                    var item = JsonSerializer.Deserialize(json, QuarantineJsonContext.Default.QuarantineItemModel);
                    if (item != null)
                    {
                        quarantineItems.Add(item);
                    }
                }
                catch
                {
                    // 跳过无法解析的文件
                }
            }

            return quarantineItems;
        }

        public static async Task<bool> AddToQuarantine(string filePath, string threatName)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
                return false;

            try
            {
                var fileHash = await CalculateFileHashAsync(filePath);

                var current = GetQuarantineItems();
                if (current.Any(x => string.Equals(x.FileHash, fileHash, StringComparison.OrdinalIgnoreCase)))
                {
                    File.Delete(filePath);
                    return true; // 已存在，不重复添加
                }

                byte[] fileData = await File.ReadAllBytesAsync(filePath);

                using var aes = Aes.Create();
                aes.KeySize = 256;
                aes.GenerateKey();
                aes.GenerateIV();

                byte[] encrypted = EncryptData(fileData, aes.Key, aes.IV);

                var item = new QuarantineItemModel
                {
                    FileHash = fileHash,
                    FileData = encrypted,
                    SourcePath = filePath,
                    ThreatName = threatName ?? string.Empty,
                    EncryptionKey = Convert.ToBase64String(aes.Key),
                    IV = Convert.ToBase64String(aes.IV)
                };

                string quarantineItemFilePath = Path.Combine(QuarantineFolderPath, $"{fileHash}.json");
                string json = JsonSerializer.Serialize(item, QuarantineJsonContext.Default.QuarantineItemModel);
                await File.WriteAllTextAsync(quarantineItemFilePath, json);

                File.Delete(filePath);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static async Task<bool> RestoreFile(string fileHash)
        {
            if (string.IsNullOrWhiteSpace(fileHash))
                return false;

            var current = GetQuarantineItems();
            var item = current.FirstOrDefault(x => string.Equals(x.FileHash, fileHash, StringComparison.OrdinalIgnoreCase));
            if (item == null)
                return false;

            try
            {
                string targetPath = item.SourcePath;

                if (File.Exists(targetPath))
                {
                    string dir = Path.GetDirectoryName(targetPath) ?? "";
                    string nameNoExt = Path.GetFileNameWithoutExtension(targetPath);
                    string ext = Path.GetExtension(targetPath);
                    targetPath = Path.Combine(dir, $"{nameNoExt}_restored{ext}");
                }

                byte[] key = Convert.FromBase64String(item.EncryptionKey);
                byte[] iv = Convert.FromBase64String(item.IV);

                byte[] plain = DecryptData(item.FileData, key, iv);
                await File.WriteAllBytesAsync(targetPath, plain);

                string quarantineItemFilePath = Path.Combine(QuarantineFolderPath, $"{fileHash}.json");
                if (File.Exists(quarantineItemFilePath))
                {
                    File.Delete(quarantineItemFilePath);
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        public static async Task<bool> DeleteItem(string fileHash)
        {
            if (string.IsNullOrWhiteSpace(fileHash))
                return false;

            string quarantineItemFilePath = Path.Combine(QuarantineFolderPath, $"{fileHash}.json");

            if (File.Exists(quarantineItemFilePath))
            {
                File.Delete(quarantineItemFilePath);
                return true;
            }

            return false;
        }

        public static async Task<int> DeleteItems(IEnumerable<string> fileHashes)
        {
            var set = new HashSet<string>(
                fileHashes.Where(s => !string.IsNullOrWhiteSpace(s)),
                StringComparer.OrdinalIgnoreCase
            );

            if (set.Count == 0)
                return 0;

            int removed = 0;
            foreach (var fileHash in set)
            {
                string quarantineItemFilePath = Path.Combine(QuarantineFolderPath, $"{fileHash}.json");
                if (File.Exists(quarantineItemFilePath))
                {
                    File.Delete(quarantineItemFilePath);
                    removed++;
                }
            }

            return removed;
        }

        public static async Task<bool> ClearQuarantine()
        {
            if (Directory.Exists(QuarantineFolderPath))
            {
                foreach (var file in Directory.GetFiles(QuarantineFolderPath))
                {
                    File.Delete(file);
                }
            }

            return true;
        }

        private static async Task<string> CalculateFileHashAsync(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hashBytes = await sha256.ComputeHashAsync(stream);
            return Convert.ToHexStringLower(hashBytes);
        }

        private static byte[] EncryptData(byte[] data, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;

            using var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(data, 0, data.Length);
                cs.FlushFinalBlock();
            }
            return ms.ToArray();
        }

        private static byte[] DecryptData(byte[] encryptedData, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;

            using var input = new MemoryStream(encryptedData);
            using var cs = new CryptoStream(input, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var output = new MemoryStream();
            cs.CopyTo(output);
            return output.ToArray();
        }
    }
}