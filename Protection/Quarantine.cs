using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Xdows.Protection
{
    /// <summary>
    /// 隔离区项目模型
    /// </summary>
    public class QuarantineItem
    {
        /// <summary>
        /// 原始文件路径
        /// </summary>
        public string OriginalPath { get; set; } = string.Empty;
        
        /// <summary>
        /// 隔离文件路径
        /// </summary>
        public string QuarantinePath { get; set; } = string.Empty;
        
        /// <summary>
        /// 文件名
        /// </summary>
        public string FileName { get; set; } = string.Empty;
        
        /// <summary>
        /// 隔离时间
        /// </summary>
        public DateTime QuarantineDate { get; set; } = DateTime.Now;
        
        /// <summary>
        /// 格式化的隔离时间（用于显示）
        /// </summary>
        public string FormattedQuarantineDate => QuarantineDate.ToString("yyyy-MM-dd HH:mm:ss");
        
        /// <summary>
        /// 检测到的病毒名称
        /// </summary>
        public string VirusName { get; set; } = string.Empty;
        
        /// <summary>
        /// 文件大小（字节）
        /// </summary>
        public long FileSize { get; set; }
        
        /// <summary>
        /// 文件哈希值
        /// </summary>
        public string FileHash { get; set; } = string.Empty;
        
        /// <summary>
        /// 加密密钥（Base64编码）
        /// </summary>
        public string EncryptionKey { get; set; } = string.Empty;
        
        /// <summary>
        /// 初始化向量（Base64编码）
        /// </summary>
        public string IV { get; set; } = string.Empty;
    }

    /// <summary>
    /// 隔离区管理器
    /// </summary>
    public static class QuarantineManager
    {
        private static readonly string QuarantineFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Xdows", "Quarantine");
        private static readonly string QuarantineDataFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Xdows", "quarantine_data.json");
        private static List<QuarantineItem> _quarantineItems = new List<QuarantineItem>();
        
        /// <summary>
        /// 初始化隔离区
        /// </summary>
        public static void Initialize()
        {
            try
            {
                // 确保隔离区文件夹存在
                if (!Directory.Exists(QuarantineFolder))
                {
                    Directory.CreateDirectory(QuarantineFolder);
                }
                
                // 加载隔离区数据
                LoadQuarantineData();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"初始化隔离区失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 添加文件到隔离区
        /// </summary>
        /// <param name="originalPath">原始文件路径</param>
        /// <param name="virusName">检测到的病毒名称</param>
        /// <returns>是否成功添加到隔离区</returns>
        public static bool AddToQuarantine(string originalPath, string virusName)
        {
            try
            {
                if (!File.Exists(originalPath))
                    return false;
                
                // 生成唯一的隔离文件名
                string fileName = Path.GetFileName(originalPath);
                string quarantineFileName = $"{Guid.NewGuid()}_{fileName}";
                string quarantineFilePath = Path.Combine(QuarantineFolder, quarantineFileName);
                
                // 生成加密密钥和IV
                using (Aes aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.GenerateKey();
                    aes.GenerateIV();
                    
                    // 加密文件
                    EncryptFile(originalPath, quarantineFilePath, aes.Key, aes.IV);
                    
                    // 获取原始文件大小
                    FileInfo originalFileInfo = new FileInfo(originalPath);
                    
                    // 创建隔离项
                    var quarantineItem = new QuarantineItem
                    {
                        OriginalPath = originalPath,
                        QuarantinePath = quarantineFilePath,
                        FileName = fileName,
                        QuarantineDate = DateTime.Now,
                        VirusName = virusName,
                        FileSize = originalFileInfo.Length,
                        FileHash = CalculateFileHash(originalPath),
                        EncryptionKey = Convert.ToBase64String(aes.Key),
                        IV = Convert.ToBase64String(aes.IV)
                    };
                    
                    // 添加到列表
                    _quarantineItems.Add(quarantineItem);
                    
                    // 保存数据
                    SaveQuarantineData();
                    
                    // 删除原始文件
                    File.Delete(originalPath);
                }
                
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"添加文件到隔离区失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 从隔离区恢复文件
        /// </summary>
        /// <param name="itemId">隔离项ID</param>
        /// <returns>是否成功恢复</returns>
        public static bool RestoreFromQuarantine(string itemId)
        {
            try
            {
                var item = _quarantineItems.Find(q => q.QuarantinePath.Contains(itemId));
                if (item == null)
                    return false;
                
                // 检查原始位置是否已存在同名文件
                if (File.Exists(item.OriginalPath))
                {
                    // 如果存在，生成新文件名
                    string directory = Path.GetDirectoryName(item.OriginalPath) ?? "";
                    string fileNameWithoutExt = Path.GetFileNameWithoutExtension(item.OriginalPath);
                    string extension = Path.GetExtension(item.OriginalPath);
                    string newFileName = $"{fileNameWithoutExt}_restored{extension}";
                    item.OriginalPath = Path.Combine(directory, newFileName);
                }
                
                // 解密文件到原始路径
                byte[] key = Convert.FromBase64String(item.EncryptionKey);
                byte[] iv = Convert.FromBase64String(item.IV);
                DecryptFile(item.QuarantinePath, item.OriginalPath, key, iv);
                
                // 从列表中移除
                _quarantineItems.Remove(item);
                
                // 保存数据
                SaveQuarantineData();
                
                // 删除隔离文件
                File.Delete(item.QuarantinePath);
                
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"从隔离区恢复文件失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 从隔离区删除文件
        /// </summary>
        /// <param name="itemId">隔离项ID</param>
        /// <returns>是否成功删除</returns>
        public static bool DeleteFromQuarantine(string itemId)
        {
            try
            {
                var item = _quarantineItems.Find(q => q.QuarantinePath.Contains(itemId));
                if (item == null)
                    return false;
                
                // 删除隔离的加密文件
                File.Delete(item.QuarantinePath);
                
                // 从列表中移除
                _quarantineItems.Remove(item);
                
                // 保存数据
                SaveQuarantineData();
                
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"从隔离区删除文件失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 清空隔离区
        /// </summary>
        /// <returns>是否成功清空</returns>
        public static bool ClearQuarantine()
        {
            try
            {
                // 删除所有隔离文件
                foreach (var item in _quarantineItems)
                {
                    try
                    {
                        if (File.Exists(item.QuarantinePath))
                        {
                            File.Delete(item.QuarantinePath);
                        }
                    }
                    catch
                    {
                        // 忽略单个文件删除失败
                    }
                }
                
                // 清空列表
                _quarantineItems.Clear();
                
                // 保存数据
                SaveQuarantineData();
                
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"清空隔离区失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 获取隔离区项目列表
        /// </summary>
        /// <returns>隔离区项目列表</returns>
        public static List<QuarantineItem> GetQuarantineItems()
        {
            return new List<QuarantineItem>(_quarantineItems);
        }
        
        /// <summary>
        /// 获取隔离区项目数量
        /// </summary>
        /// <returns>隔离区项目数量</returns>
        public static int GetQuarantineCount()
        {
            return _quarantineItems.Count;
        }
        
        /// <summary>
        /// 保存隔离区数据
        /// </summary>
        private static void SaveQuarantineData()
        {
            try
            {
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true
                };
                
                string json = JsonSerializer.Serialize(_quarantineItems, options);
                File.WriteAllText(QuarantineDataFile, json);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"保存隔离区数据失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 加载隔离区数据
        /// </summary>
        private static void LoadQuarantineData()
        {
            try
            {
                if (!File.Exists(QuarantineDataFile))
                    return;
                
                string json = File.ReadAllText(QuarantineDataFile);
                var items = JsonSerializer.Deserialize<List<QuarantineItem>>(json);
                
                if (items != null)
                {
                    _quarantineItems = items;
                    
                    // 验证隔离文件是否仍然存在
                    for (int i = _quarantineItems.Count - 1; i >= 0; i--)
                    {
                        if (!File.Exists(_quarantineItems[i].QuarantinePath))
                        {
                            _quarantineItems.RemoveAt(i);
                        }
                    }
                    
                    // 如果有变化，保存更新后的数据
                    SaveQuarantineData();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"加载隔离区数据失败: {ex.Message}");
                _quarantineItems = new List<QuarantineItem>();
            }
        }
        
        /// <summary>
        /// 计算文件哈希值
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>文件哈希值</returns>
        private static string CalculateFileHash(string filePath)
        {
            try
            {
                using var md5 = System.Security.Cryptography.MD5.Create();
                using var stream = File.OpenRead(filePath);
                byte[] hashBytes = md5.ComputeHash(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
            catch
            {
                return string.Empty;
            }
        }
        
        /// <summary>
        /// 加密文件
        /// </summary>
        /// <param name="inputFile">输入文件路径</param>
        /// <param name="outputFile">输出文件路径</param>
        /// <param name="key">加密密钥</param>
        /// <param name="iv">初始化向量</param>
        private static void EncryptFile(string inputFile, string outputFile, byte[] key, byte[] iv)
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                    
                    using (FileStream inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                    using (FileStream outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))
                    {
                        inputStream.CopyTo(cryptoStream);
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"加密文件失败: {ex.Message}");
                throw;
            }
        }
        
        /// <summary>
        /// 解密文件
        /// </summary>
        /// <param name="inputFile">输入文件路径</param>
        /// <param name="outputFile">输出文件路径</param>
        /// <param name="key">解密密钥</param>
        /// <param name="iv">初始化向量</param>
        private static void DecryptFile(string inputFile, string outputFile, byte[] key, byte[] iv)
        {
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                    
                    using (FileStream inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                    using (FileStream outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                    using (CryptoStream cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read))
                    {
                        cryptoStream.CopyTo(outputStream);
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"解密文件失败: {ex.Message}");
                throw;
            }
        }
    }
}