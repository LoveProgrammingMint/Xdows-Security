using PublicPart;
using System.Security.Cryptography;
using System.Text.Json;

namespace ScanEngine
{
    public static class ScanEngine
    {

        public static async Task<string> LocalScanAsync(string path, bool deep, bool ExtraData) => Xdows_Local.Core.ScanAsync(path, deep, ExtraData);

        private static readonly System.Net.Http.HttpClient s_httpClient = new() { Timeout = TimeSpan.FromSeconds(10) };
        public static async Task<(int statusCode, string? result)> CzkCloudScanAsync(string path, string apiKey)
        {
            var client = s_httpClient;
            string hash = await GetFileMD5Async(path);
            string url = $"https://cv.szczk.top/scan/{apiKey}/{hash}";
            try
            {
                var resp = await client.GetAsync(url);
                resp.EnsureSuccessStatusCode();
                string json = await resp.Content.ReadAsStringAsync();
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
            var client = s_httpClient;
            string hash = await GetFileMD5Async(path);
            string url = $"http://103.118.245.82:5000/scan/md5?key=my_virus_key_2024&md5={hash}";
            try
            {
                var resp = await client.GetAsync(url);
                resp.EnsureSuccessStatusCode();
                string json = await resp.Content.ReadAsStringAsync();
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
        public static async Task<string> GetFileMD5Async(string path)
        {
            using var md5 = MD5.Create();
            await using var stream = File.OpenRead(path);
            var hash = await md5.ComputeHashAsync(stream);
            return Convert.ToHexString(hash);
        }
        public class SouXiaoEngineScan
        {
            private readonly Boolean IsDebug = true;
            private readonly SouXiao.EngineEntry SouXiaoCoreV2026 = new();

            public bool Initialize()
            {
                try
                {
                    return SouXiaoCoreV2026.Initialize();
                }
                catch (Exception)
                {
                    if (IsDebug) { throw; }
                    return false;
                }
            }

            public (bool IsVirus, string Result) ScanFile(string path)
            {
                try
                {
                    if (SouXiaoCoreV2026 == null)
                    {
                        throw new InvalidOperationException("SouXiaoCore is not initialized.");
                    }
                    var scanResult = SouXiaoCoreV2026.Scan(path);
                    foreach (var item in scanResult)
                    {
                        foreach (var item1 in item.Value)
                        {
                            if (!(item1 == EngineResult.Safe || item1 == EngineResult.UnSupport))
                            {
                                return (true, $"SouXiao.Heuristic.{item.Key}");
                            }
                        }
                    }
                    return (false, string.Empty);
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
