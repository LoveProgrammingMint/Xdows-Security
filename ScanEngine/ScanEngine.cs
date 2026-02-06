using Self_Heuristic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
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
            private LiuLiV5Classifier? SouXiaoCore;
            private readonly Boolean IsDebug = true;

            public bool Initialize()
            {
                try
                {
                    SouXiaoCore = new(Directory.GetCurrentDirectory()+"\\LiuLi.onnx");
                    return true;
                }
                catch (Exception)
                {
                    if (IsDebug) { throw; }
                    return false;
                }
            }

            public static (bool IsVirus, string Result) ScanFileByRuleEngine(string path)
            {
                return (false, string.Empty);
            }

            public (bool IsVirus, string Result) ScanFile(string path)
            {
                try
                {
                    if (SouXiaoCore == null)
                    {
                        throw new InvalidOperationException("SouXiaoCore is not initialized.");
                    }
                    bool scanResult = SouXiaoCore.Predict(path);
                    if (scanResult)
                    {
                        return (true, "SouXiao.Heuristic.LIULIv5");
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


        public static async Task<(int statusCode, string? result)> AXScanFileAsync(string targetFilePath)
        {
            if (!File.Exists(targetFilePath))
                throw new FileNotFoundException($"Target file not found: {targetFilePath}");

            string baseDir = AppContext.BaseDirectory;
            string axApiExePath = Path.Combine(baseDir, "AX_API", "AX_API.exe");

            if (!File.Exists(axApiExePath))
                throw new FileNotFoundException($"AX_API.exe not found at: {axApiExePath}");

            string escapedTargetPath = $"\"{targetFilePath}\"";

            var startInfo = new ProcessStartInfo
            {
                FileName = axApiExePath,
                Arguments = $"-PE \"{escapedTargetPath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            using var process = new Process { StartInfo = startInfo };

            try
            {
                process.Start();

                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();

                await process.WaitForExitAsync();

                string output = await outputTask;
                string error = await errorTask;

                string result = !string.IsNullOrEmpty(output) ? output : error;
                using var doc = JsonDocument.Parse(result);

                if (doc.RootElement.TryGetProperty("status", out var statusProp) &&
                    statusProp.GetString() == "success")
                {
                    if (doc.RootElement.TryGetProperty("detected_threats", out var threatsArray) &&
                        threatsArray.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var threat in threatsArray.EnumerateArray())
                        {
                            if (threat.TryGetProperty("type", out var typeProp))
                            {
                                return (200, typeProp.GetString() ?? string.Empty);
                            }
                        }

                        return (-1, string.Empty);
                    }
                }

                return (-1, string.Empty);
            }
            catch (Exception ex)
            {
                return (-1, $"Exception during scan: {ex.Message}");
            }
        }
    }
}