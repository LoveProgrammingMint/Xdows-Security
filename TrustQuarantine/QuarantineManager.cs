using Compatibility.Windows.Storage;
using System.Security.Cryptography;
using System.Text.Json;

namespace TrustQuarantine
{
    public static class QuarantineManager
    {
        private const string QuarantineDataKey = "QuarantineData";

        // 建议：固定 JsonOptions，避免后续扩展字段时不一致
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = false,
            PropertyNameCaseInsensitive = true
        };

        public static List<QuarantineItemModel> GetQuarantineItems()
        {
            if (ApplicationData.Current.LocalSettings.Values[QuarantineDataKey] is not string json ||
                string.IsNullOrWhiteSpace(json))
            {
                return [];
            }

            try
            {
                return JsonSerializer.Deserialize<List<QuarantineItemModel>>(json, JsonOptions) ?? [];
            }
            catch
            {
                // 数据坏了就当空
                return [];
            }
        }

        /// <summary>
        /// 添加文件到隔离区：读取原文件 -> AES 加密保存 -> 持久化 -> 删除原文件
        /// </summary>
        public static async Task<bool> AddToQuarantine(string filePath, string threatName)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath)) return false;

            try
            {
                var fileHash = await CalculateFileHashAsync(filePath);

                var current = GetQuarantineItems();
                if (current.Any(x => string.Equals(x.FileHash, fileHash, StringComparison.OrdinalIgnoreCase)))
                {
                    // 已存在：仍然删除原文件？这里选择不删，避免误删
                    return true;
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

                current.Add(item);
                await SaveQuarantineItemsAsync(current);

                // 入库成功后再删原文件
                File.Delete(filePath);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 从隔离区恢复文件（解密写回原路径，如冲突则改名），并从隔离区移除该项
        /// </summary>
        public static async Task<bool> RestoreFile(string fileHash)
        {
            if (string.IsNullOrWhiteSpace(fileHash)) return false;

            var current = GetQuarantineItems();
            var item = current.FirstOrDefault(x => string.Equals(x.FileHash, fileHash, StringComparison.OrdinalIgnoreCase));
            if (item == null) return false;

            try
            {
                string targetPath = item.SourcePath;

                // 目标路径冲突：自动改名
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

                current.Remove(item);
                await SaveQuarantineItemsAsync(current);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 单独删除隔离项（仅移除隔离记录，不恢复文件）
        /// </summary>
        public static async Task<bool> DeleteItem(string fileHash)
        {
            if (string.IsNullOrWhiteSpace(fileHash)) return false;

            var current = GetQuarantineItems();
            int removed = current.RemoveAll(x => string.Equals(x.FileHash, fileHash, StringComparison.OrdinalIgnoreCase));
            if (removed <= 0) return false;

            await SaveQuarantineItemsAsync(current);
            return true;
        }

        /// <summary>
        /// 批量删除隔离项
        /// </summary>
        public static async Task<int> DeleteItems(IEnumerable<string> fileHashes)
        {
            var set = new HashSet<string>(fileHashes.Where(s => !string.IsNullOrWhiteSpace(s)),
                                          StringComparer.OrdinalIgnoreCase);
            if (set.Count == 0) return 0;

            var current = GetQuarantineItems();
            int before = current.Count;
            current.RemoveAll(x => set.Contains(x.FileHash));
            int removed = before - current.Count;

            if (removed > 0)
                await SaveQuarantineItemsAsync(current);

            return removed;
        }

        public static async Task<bool> ClearQuarantine()
        {
            await SaveQuarantineItemsAsync([]);
            return true;
        }

        private static async Task SaveQuarantineItemsAsync(List<QuarantineItemModel> items)
        {
            string json = JsonSerializer.Serialize(items, JsonOptions);
            ApplicationData.Current.LocalSettings.Values[QuarantineDataKey] = json;
            await Task.CompletedTask;
        }

        private static async Task<string> CalculateFileHashAsync(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hashBytes = await sha256.ComputeHashAsync(stream);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
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
