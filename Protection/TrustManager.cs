using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Xdows.Protection
{
    /// <summary>
    /// 信任区项目模型
    /// </summary>
    public class TrustItem
    {
        /// <summary>
        /// 信任项ID
        /// </summary>
        public string Id { get; set; } = Guid.NewGuid().ToString();
        
        /// <summary>
        /// 文件或文件夹路径
        /// </summary>
        public string Path { get; set; } = string.Empty;
        
        /// <summary>
        /// 类型：文件或文件夹
        /// </summary>
        public TrustItemType Type { get; set; }
        
        /// <summary>
        /// 文件名或文件夹名
        /// </summary>
        public string Name { get; set; } = string.Empty;
        
        /// <summary>
        /// 添加时间
        /// </summary>
        public DateTime AddedDate { get; set; } = DateTime.Now;
        
        /// <summary>
        /// 格式化的添加时间（用于显示）
        /// </summary>
        public string FormattedAddedDate => AddedDate.ToString("yyyy-MM-dd HH:mm:ss");
        
        /// <summary>
        /// 文件大小（如果是文件）
        /// </summary>
        public long FileSize { get; set; }
        
        /// <summary>
        /// 备注
        /// </summary>
        public string Note { get; set; } = string.Empty;
    }
    
    /// <summary>
    /// 信任项类型枚举
    /// </summary>
    public enum TrustItemType
    {
        File,
        Folder
    }
    
    /// <summary>
    /// 信任区管理器
    /// </summary>
    public static class TrustManager
    {
        private static readonly string TrustDataFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Xdows", "trust_data.json");
        private static List<TrustItem> _trustItems = new List<TrustItem>();
        
        /// <summary>
        /// 初始化信任区
        /// </summary>
        public static void Initialize()
        {
            try
            {
                // 确保数据目录存在
                string dataDir = Path.GetDirectoryName(TrustDataFile) ?? "";
                if (!Directory.Exists(dataDir))
                {
                    Directory.CreateDirectory(dataDir);
                }
                
                // 加载信任区数据
                LoadTrustData();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"初始化信任区失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 添加文件到信任区
        /// </summary>
        /// <param name="path">文件路径</param>
        /// <param name="note">备注</param>
        /// <returns>是否成功添加到信任区</returns>
        public static bool AddFileToTrust(string path, string note = "")
        {
            try
            {
                if (!File.Exists(path))
                    return false;
                
                // 检查是否已存在
                if (IsPathTrusted(path))
                    return true;
                
                // 获取文件信息
                FileInfo fileInfo = new FileInfo(path);
                string fileName = Path.GetFileName(path);
                
                // 创建信任项
                var trustItem = new TrustItem
                {
                    Path = path,
                    Type = TrustItemType.File,
                    Name = fileName,
                    AddedDate = DateTime.Now,
                    FileSize = fileInfo.Length,
                    Note = note
                };
                
                // 添加到列表
                _trustItems.Add(trustItem);
                
                // 保存数据
                SaveTrustData();
                
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"添加文件到信任区失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 添加文件夹到信任区
        /// </summary>
        /// <param name="path">文件夹路径</param>
        /// <param name="note">备注</param>
        /// <returns>是否成功添加到信任区</returns>
        public static bool AddFolderToTrust(string path, string note = "")
        {
            try
            {
                if (!Directory.Exists(path))
                    return false;
                
                // 检查是否已存在
                if (IsPathTrusted(path))
                    return true;
                
                // 获取文件夹信息
                DirectoryInfo dirInfo = new DirectoryInfo(path);
                string folderName = Path.GetFileName(path);
                
                // 创建信任项
                var trustItem = new TrustItem
                {
                    Path = path,
                    Type = TrustItemType.Folder,
                    Name = folderName,
                    AddedDate = DateTime.Now,
                    Note = note
                };
                
                // 添加到列表
                _trustItems.Add(trustItem);
                
                // 保存数据
                SaveTrustData();
                
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"添加文件夹到信任区失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 从信任区移除项目
        /// </summary>
        /// <param name="id">信任项ID</param>
        /// <returns>是否成功移除</returns>
        public static bool RemoveFromTrust(string id)
        {
            try
            {
                var item = _trustItems.Find(t => t.Id == id);
                if (item == null)
                    return false;
                
                _trustItems.Remove(item);
                
                // 保存数据
                SaveTrustData();
                
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"从信任区移除项目失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 获取所有信任项
        /// </summary>
        /// <returns>信任项列表</returns>
        public static List<TrustItem> GetTrustItems()
        {
            return new List<TrustItem>(_trustItems);
        }
        
        /// <summary>
        /// 检查路径是否在信任区中
        /// </summary>
        /// <param name="path">要检查的路径</param>
        /// <returns>是否在信任区中</returns>
        public static bool IsPathTrusted(string path)
        {
            if (string.IsNullOrEmpty(path))
                return false;
            
            // 检查直接匹配
            if (_trustItems.Any(t => string.Equals(t.Path, path, StringComparison.OrdinalIgnoreCase)))
                return true;
            
            // 检查文件是否在信任的文件夹中
            foreach (var item in _trustItems.Where(t => t.Type == TrustItemType.Folder))
            {
                if (path.StartsWith(item.Path + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                    path.StartsWith(item.Path + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            
            return false;
        }
        
        /// <summary>
        /// 清空信任区
        /// </summary>
        /// <returns>是否成功清空</returns>
        public static bool ClearTrust()
        {
            try
            {
                _trustItems.Clear();
                
                // 保存数据
                SaveTrustData();
                
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"清空信任区失败: {ex.Message}");
                return false;
            }
        }
        
        /// <summary>
        /// 保存信任区数据
        /// </summary>
        private static void SaveTrustData()
        {
            try
            {
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                
                string json = JsonSerializer.Serialize(_trustItems, options);
                File.WriteAllText(TrustDataFile, json);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"保存信任区数据失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 加载信任区数据
        /// </summary>
        private static void LoadTrustData()
        {
            try
            {
                if (!File.Exists(TrustDataFile))
                    return;
                
                string json = File.ReadAllText(TrustDataFile);
                var items = JsonSerializer.Deserialize<List<TrustItem>>(json);
                
                if (items != null)
                {
                    _trustItems = items;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"加载信任区数据失败: {ex.Message}");
                _trustItems = new List<TrustItem>();
            }
        }
    }
}