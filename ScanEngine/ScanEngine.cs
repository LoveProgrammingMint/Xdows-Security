using PeNet;
using Self_Heuristic;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace Xdows.ScanEngine
{
    public static class ScanEngine
    {
        public class PEInfo
        {
            public string[]? ImportsDll;
            public string[]? ImportsName;
            public string[]? ExportsName;
        }

        public static async Task<string> LocalScanAsync(string path, bool deep, bool ExtraData)
        {
            if (!File.Exists(path) || !PeFile.IsPeFile(path)) return string.Empty;

            var peFile = new PeFile(path);
            var fileInfo = new PEInfo();

            if (peFile.IsDll) {
                var exports = peFile.ExportedFunctions;
                if (exports != null)
                {
                    fileInfo.ExportsName = [.. exports.Select(exported => exported.Name?? string.Empty)];
                }
                else
                {
                    fileInfo.ExportsName = Array.Empty<string>();
                }
            }
            var importedFunctions = peFile.ImportedFunctions;
            if (importedFunctions != null)
            {
                var validImports = importedFunctions
                    .Where(import => import.Name != null)
                    .ToList();

                fileInfo.ImportsDll = validImports.Select(import => import.DLL).ToArray();
                fileInfo.ImportsName = [.. validImports.Select(import => import.Name ?? string.Empty)];
            }
            else
            {
                fileInfo.ImportsDll = Array.Empty<string>();
                fileInfo.ImportsName = Array.Empty<string>();
            }

            var score = await Heuristic.Evaluate(path,peFile, fileInfo, deep);
            if (score.score >= 75)
            {
                return ExtraData ? $"Xdows.local.code{score.score} {score.extra}" : $"Xdows.local.code{score.score}";
            }
            return string.Empty;
        }
        //public static string SignedAndValid = string.Empty;

        public static async Task<(int statusCode, string? result)> CzkCloudScanAsync(string path, string apiKey)
        {
            using var client = new HttpClient();
            string hash = await GetFileMD5Async(path);
            string url = $"https://cv.szczk.top/scan/{apiKey}/{hash}";
            try
            {
                string json = await client.GetStringAsync(url);
                using JsonDocument doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("result", out JsonElement prop))
                    return (200, prop.GetString());
            }
            catch (HttpRequestException ex)
            {
                return ((int?)ex.StatusCode ?? -1, string.Empty);
            }

            return (-1, string.Empty);
        }
        public static async Task<(int statusCode, string? result)> CloudScanAsync(string path)
        {
            using var client = new HttpClient();
            string hash = await GetFileMD5Async(path);
            string url = $"http://103.118.245.82:5000/scan/md5?key=my_virus_key_2024&md5={hash}";
            try
            {
                string json = await client.GetStringAsync(url);
                using JsonDocument doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("scan_result", out JsonElement prop))
                    return (200, prop.GetString());
            }
            catch (HttpRequestException ex)
            {
                return ((int?)ex.StatusCode ?? -1, string.Empty);
            }

            return (-1, string.Empty);
        }
        private static async Task<string> GetFileMD5Async(string path)
        {
            using var md5 = MD5.Create();
            await using var stream = File.OpenRead(path);
            var hash = await md5.ComputeHashAsync(stream);
            return Convert.ToHexString(hash);
        }
        public class SouXiaoEngineScan
        {
            private Core? SouXiaoCore;
            private Boolean IsDebug = false;

            public bool Initialize()
            {
                try
                {
                    SouXiaoCore = new(0.8, Directory.GetCurrentDirectory());
                    return true;
                }
                catch (Exception)
                {
                    throw;
                    //return false;
                }
            }
            public (bool IsVirus,string Result) ScanFile(string path)
            {
                try
                {
                    if (SouXiaoCore == null)
                    {
                        throw new InvalidOperationException("SouXiaoCore is not initialized.");
                    }
                    bool scanResult = SouXiaoCore.Run(path);
                    if (scanResult)
                    {
                        return (true, "SouXiao.Hit");
                    }
                    else
                    {
                        return (false, string.Empty);
                    }
                }
                catch (Exception)
                {
                    if (IsDebug) { throw; }

                    return (false, string.Empty);
                }
            }
        }
    }
}