using PeNet;
using SouXiaoEngine;
using SouXiaoEngine.APIs;
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
            if (!File.Exists(path)) return string.Empty;

            var md5 = await GetFileMD5Async(path);
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
                if (DllScan.Scan(path, fileInfo))
                    return "Xdows.local.DllVirus";
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

            var score = Heuristic.Evaluate(path, fileInfo, deep, out var extra);
            if (score >= 75)
            {
                return ExtraData ? $"Xdows.local.code{score} {extra}" : $"Xdows.local.code{score}";
            }
            return string.Empty;
        }
        public static async Task<(int statusCode, string? result)> CloudScanAsync(string path, string apiKey)
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
        private static async Task<string> GetFileMD5Async(string path)
        {
            using var md5 = MD5.Create();
            await using var stream = File.OpenRead(path);
            var hash = await md5.ComputeHashAsync(stream);
            return Convert.ToHexString(hash);
        }
        public class SouXiaoEngineScan
        {
            private readonly EngineV3Apis engineV3Apis = new(AppDomain.CurrentDomain.BaseDirectory);
            public bool Initialize()
            {
                try
                {
                    engineV3Apis.V3Ex_API_SetSetting(true, true, true, true, true, false);
                    engineV3Apis.V3Ex_API_LoadLib();
                    return engineV3Apis.V3Ex_API_GetLibState() != MalwareMd5Check.States.NotInitialized;
                }
                catch
                {
                    return false;
                }
            }
            public (bool IsVirus,string Result) ScanFile(string path)
            {
                try {
                    var result = engineV3Apis.V3Ex_API_ScanFile(path);
                    return (result.Item1, result.Item2.ToString());
                }
                catch 
                {
                    return (false, string.Empty);
                }
            }
        }
    }
}