using Compatibility.Windows.Storage;
using Helper;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.Windows.Globalization;
using Protection;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using WinUI3Localizer;
using static Protection.CallBack;

namespace Xdows_Security
{
    public record UpdateInfo
    {
        public required string Title { get; set; }
        public required string Content { get; set; }
        public required string DownloadUrl { get; set; }
    }

    public static class Updater
    {
        private static readonly HttpClient _httpClient = new();

        static Updater()
        {
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd($"{AppInfo.AppId}/{AppInfo.AppVersion}");
        }

        public static async Task<UpdateInfo?> CheckUpdateAsync()
        {
            try
            {
                const string url = "https://api.github.com/repositories/1032964256/releases/latest";
                string json = await _httpClient.GetStringAsync(url);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                string? title = root.GetProperty("name").GetString()
                               ?? root.GetProperty("tag_name").GetString();

                string? content = root.GetProperty("body").GetString();

                string? downloadUrl = null;
                if (root.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
                {
                    foreach (var asset in assets.EnumerateArray())
                    {
                        if (asset.TryGetProperty("browser_download_url", out var urlProp))
                        {
                            downloadUrl = urlProp.GetString();
                            break;
                        }
                    }
                }

                downloadUrl ??= root.GetProperty("html_url").GetString();

                return new UpdateInfo
                {
                    Title = title ?? string.Empty,
                    Content = content ?? string.Empty,
                    DownloadUrl = downloadUrl ?? string.Empty
                };
            }
            catch
            {
                return null; // 或可抛出异常，依需求而定
            }
        }
    }
    public class AppInfo
    {
        public static readonly string AppName = "Xdows Security";
        public static readonly string AppId = "Xdows-Security";
        public static readonly string AppVersion = "5.0.0";
        public static readonly string AppFeedback = "https://github.com/LoveProgrammingMint/Xdows-Security/issues/new/choose";
        public static readonly string AppWebsite = "https://docs.xiguastudio.top/";
        // 修改 开发团队、Xdows Tools 名称请修改本地化资源文件
    }
    public static class ProtectionStatus
    {
        public static bool IsOpen()
        {
            return true;
        }

        private static readonly InterceptCallBack interceptCallBack = (isSucceed, path, type) =>
        {
            LogText.AddNewLog(LogText.LogLevel.WARN, "Protection", isSucceed
                ? $"InterceptProcess：{Path.GetFileName(path)}"
                : $"Cannot InterceptProcess：{Path.GetFileName(path)}");
            // string content = isSucceed ? "已发现威胁" : "无法处理威胁";
            // content = $"{AppInfo.AppName} {content}.{Environment.NewLine}相关数据：{Path.GetFileName(path)}{Environment.NewLine}单击此通知以查看详细信息";
            _ = (App.MainWindow?.DispatcherQueue?.TryEnqueue(() =>
            {
                _ = InterceptWindow.ShowOrActivate(new InterceptWindowHelper.InterceptWindowSetting
                {
                    path = path,
                    isSucceed = isSucceed,
                    interceptWindowButtonType = InterceptWindowHelper.InterceptWindowButtonType.RestoreOrTrust
                });
            }));
            // Notifications.ShowNotification("发现威胁", content, path);
        };
        private static readonly IProtectionModel LegacyProcessProtection = new LegacyProcessProtection();
        private static readonly IProtectionModel LegacyFilesProtection = new LegacyFilesProtection();

        private static readonly IProtectionModel ETWProcessProtection = new ETW.ProcessProtection();
        private static readonly IProtectionModel ETWFilesProtection = new ETW.FilesProtection();
        private static readonly IProtectionModel ETWRegistryProtection = new ETW.RegistryProtection();
        public static bool Run(int RunID)
        {
            IProtectionModel? protection = RunIdToProtection(RunID);

            if (protection is null) { return false; }

            if (protection.IsRun())
            {
                return protection.Stop();
            }
            else
            {
                return protection.Run(interceptCallBack);
            }
        }
        public static bool IsRun(int RunID)
        {
            return RunIdToProtection(RunID)?.IsRun() ?? false;
        }
        private static IProtectionModel? RunIdToProtection(int RunID)
        {
            IProtectionModel? protection = RunID switch
            {
                0 => ETWProcessProtection,
                1 => ETWFilesProtection,
                4 => ETWRegistryProtection,
                _ => null,
            };
            if (protection is null) { return null; }

            bool isCompatibilityMode = ApplicationData.Current.LocalSettings.Values[protection.Name + "_CompatibilityMode"] as bool? ?? false;

            if (isCompatibilityMode)
            {
                protection = RunID switch
                {
                    0 => LegacyProcessProtection,
                    1 => LegacyFilesProtection,
                    _ => null,
                };
            }

            return protection;
        }
    }

    public static class Statistics
    {
        public static int ScansQuantity { get; set; } = 0;
        public static int VirusQuantity { get; set; } = 0;
    }
    public static class LogText
    {
        private const int HOT_MAX_LINES = 500;
        private const int BATCH_SIZE = 50;
        private const int FLUSH_INTERVAL_MS = 200;
        private static readonly TimeSpan RetainAge = TimeSpan.FromDays(7);
        private static readonly string BaseFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Xdows-Security", "Logs");
        private static readonly Queue<string> _hotLines = new();
        private static readonly object _lockObj = new();
        private static readonly Channel<LogRow> _writeChannel = Channel.CreateUnbounded<LogRow>();
        private static readonly Timer _throttleTimer;
        private static bool _isTimerActive;

        public static event EventHandler? TextChanged;
        public static string Text
        {
            get
            {
                lock (_lockObj)
                {
                    return string.Join(Environment.NewLine, _hotLines);
                }
            }
        }

        public static void ClearLog()
        {
            lock (_lockObj)
            {
                _hotLines.Clear();
            }
            TriggerTextChanged();
        }

        public static async void AddNewLog(LogLevel level, string source, string info)
        {
            var row = new LogRow
            {
                Time = DateTime.Now,
                Level = level,
                Source = source,
                Text = info,
                ThreadId = Environment.CurrentManagedThreadId
            };
            UpdateHotCache(row);
            await _writeChannel.Writer.WriteAsync(row);
        }
        static LogText()
        {
            Directory.CreateDirectory(BaseFolder);
            CleanupOldLogs();
            _ = Task.Run(WritePumpAsync);
            _throttleTimer = new Timer(OnTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
        }
        private static void UpdateHotCache(LogRow row)
        {
            string formatted = FormatRow(row);

            lock (_lockObj)
            {
                if (_hotLines.Count >= HOT_MAX_LINES)
                {
                    _hotLines.Dequeue();
                }
                _hotLines.Enqueue(formatted);
            }

            TriggerTextChanged();
        }

        private static void TriggerTextChanged()
        {
            lock (_lockObj)
            {
                if (_isTimerActive) return;
                _isTimerActive = true;
                _throttleTimer.Change(100, Timeout.Infinite);
            }
        }

        private static void OnTimerCallback(object? state)
        {
            lock (_lockObj)
            {
                _isTimerActive = false;
            }
            TextChanged?.Invoke(null, EventArgs.Empty);
        }

        private static async Task WritePumpAsync()
        {
            var batch = new List<LogRow>(BATCH_SIZE);
            var reader = _writeChannel.Reader;

            while (await reader.WaitToReadAsync())
            {
                batch.Clear();

                while (batch.Count < BATCH_SIZE && reader.TryRead(out var row))
                {
                    batch.Add(row);
                }
                if (batch.Count == 0) continue;
                try
                {
                    string filePath = GetTodayFilePath();
                    string content = string.Join(Environment.NewLine, batch.ConvertAll(FormatRow)) + Environment.NewLine;
                    await File.AppendAllTextAsync(filePath, content);
                }
                catch { }
            }
        }

        private static void CleanupOldLogs()
        {
            try
            {
                if (!Directory.Exists(BaseFolder)) return;
                var dir = new DirectoryInfo(BaseFolder);
                var cutoff = DateTime.UtcNow - RetainAge;

                foreach (var f in dir.GetFiles("logs-*.txt"))
                {
                    if (f.LastWriteTimeUtc < cutoff)
                    {
                        f.Delete();
                    }
                }
            }
            catch { }
        }
        private static string GetTodayFilePath() =>
            Path.Combine(BaseFolder, $"logs-{DateTime.Now:yyyy-MM-dd}.txt");
        private static string FormatRow(LogRow r) =>
            $"[{r.Time:yyyy-MM-dd HH:mm:ss}][{r.Level}][{r.Source}][T:{r.ThreadId}]: {r.Text}";
        public enum LogLevel
        {
            DEBUG = 0,
            INFO = 1,
            WARN = 2,
            ERROR = 3,
            FATAL = 4
        }
        private record LogRow
        {
            public DateTime Time { get; init; }
            public LogLevel Level { get; init; }
            public string Source { get; init; } = "";
            public string Text { get; init; } = "";
            public int ThreadId { get; init; }
        }
    }
    public partial class App : Application
    {
        public static MainWindow? MainWindow { get; private set; } // 主窗口实例

        public App()
        {
            LogText.AddNewLog(LogText.LogLevel.INFO, "UI Interface", "Attempting to load the MainWindow...");
            this.InitializeComponent();
        }
        protected override async void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
            try
            {
                //Helper.Linker.Start(async (interceptWindowSetting) =>
                //{
                //    var tcs = new TaskCompletionSource<string>();
                //    App.MainWindow?.DispatcherQueue?.TryEnqueue(async () =>
                //    {
                //        try
                //        {
                //            var result = await InterceptWindow.ShowOrActivate(interceptWindowSetting);
                //            tcs.TrySetResult(result);
                //        }
                //        catch (Exception ex)
                //        {
                //            tcs.TrySetException(ex);
                //        }
                //    });
                //    return await tcs.Task;
                //});
                await InitializeLocalizer();
                InitializeMainWindow();
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "App", $"Error in OnLaunched: {ex.Message}");
            }
        }
        private static void InitializeMainWindow()
        {
            try
            {
                //_ = InterceptWindow.ShowOrActivate(new InterceptWindowHelper.InterceptWindowSetting
                //{
                //    path = "This is a file",
                //    isSucceed = true,
                //});// 测试用的捏（By Shiyi）

                MainWindow ??= new MainWindow();
                MainWindow.Activate();
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.ERROR, "App", $"Error initializing MainWindow: {ex.Message}");
            }
        }
        public static ElementTheme Theme { get; set; } = ElementTheme.Default;
        public static string GetCzkCloudApiKey()
        {
            return string.Empty;
        }
        public static bool IsRunAsAdmin()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        private static async Task InitializeLocalizer()
        {
            ApplicationLanguages.PrimaryLanguageOverride = "en-US";

            string stringsPath = Path.Combine(AppContext.BaseDirectory, "Strings");

            var settings = ApplicationData.Current.LocalSettings;
            string lastLang = settings.Values["AppLanguage"] as string ?? "en-US";

            ILocalizer localizer = await new LocalizerBuilder()
                .AddStringResourcesFolderForLanguageDictionaries(stringsPath)
                .SetOptions(o => o.DefaultLanguage = lastLang)
                .Build();
            await localizer.SetLanguage(lastLang);
        }
        public static string OsName => RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? (Environment.OSVersion.Version.Build >= 22000 ? "Windows 11" : "Windows 10")
            : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "macOS" : "Linux";

        public static string OsVersion => RuntimeInformation.OSDescription;
        public static void PlayEntranceAnimation(UIElement uIElement, string kind, float finalVerticalOffset = 0f)
        {
            var visual = ElementCompositionPreview.GetElementVisual(uIElement);
            var compositor = visual.Compositor;
            const float amplitude = 40f;
            Vector3 directionOffset = kind.ToLowerInvariant() switch
            {
                "left" => new Vector3(-amplitude, 0, 0),
                "right" => new Vector3(amplitude, 0, 0),
                "up" => new Vector3(0, amplitude, 0),
                _ => new Vector3(0, amplitude, 0),
            };
            Vector3 finalOffset = new(0, finalVerticalOffset, 0);

            visual.Opacity = 0;
            visual.Offset = directionOffset + finalOffset;

            var easing = compositor.CreateCubicBezierEasingFunction(new Vector2(0, 0), new Vector2(0, 1));

            var offsetAnimation = compositor.CreateVector3KeyFrameAnimation();
            offsetAnimation.Target = "Offset";
            offsetAnimation.InsertKeyFrame(1.0f, finalOffset, easing);
            offsetAnimation.Duration = TimeSpan.FromMilliseconds(400);

            var opacityAnimation = compositor.CreateScalarKeyFrameAnimation();
            opacityAnimation.Target = "Opacity";
            opacityAnimation.InsertKeyFrame(1.0f, 1.0f, easing);
            opacityAnimation.Duration = TimeSpan.FromMilliseconds(400);

            visual.StartAnimation("Offset", offsetAnimation);
            visual.StartAnimation("Opacity", opacityAnimation);
        }
    }
}
