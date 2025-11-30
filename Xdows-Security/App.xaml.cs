using Compatibility.Windows.Storage;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Windows.Globalization;
using Xdows_Security.ViewModel;
using WinUI3Localizer;
using WinUIEx;
using Xdows.Protection;
using static Xdows.Protection.CallBack;

namespace Xdows_Security
{
    public class AppInfo { 
        public static readonly string AppName = "Xdows Security";
        public static readonly string AppVersion = "4.10-Dev";
        public static readonly string AppFeedback = "https://github.com/XTY64XTY12345/Xdows-Security/issues/new/choose";
        public static readonly string AppWebsite = "https://xty64xty.netlify.app/";
    }
    public static class Protection
    {
        public static bool IsOpen()
        {
            return true;
        }

        public static InterceptCallBack interceptCallBack = (bool isSucceed, string path, string type) =>
        {
            LogText.AddNewLog(2, "Protection", isSucceed
                ? $"InterceptProcess：{Path.GetFileName(path)}"
                : $"Cannot InterceptProcess：{Path.GetFileName(path)}");
            // string content = isSucceed ? "已发现威胁" : "无法处理威胁";
            // content = $"{AppInfo.AppName} {content}.{Environment.NewLine}相关数据：{Path.GetFileName(path)}{Environment.NewLine}单击此通知以查看详细信息";
            App.MainWindow?.DispatcherQueue?.TryEnqueue(() =>
            {
                InterceptWindow.ShowOrActivate(isSucceed, path, type);
            });
            // Notifications.ShowNotification("发现威胁", content, path);
        };

        public static bool Run(int RunID)
        {
            switch (RunID)
            {
                case 0:
                    if (ProcessProtection.IsEnabled())
                    {
                        LogText.AddNewLog(1, "Protection", $"Try to Disable ProcessProtection ...");
                        return Xdows.Protection.ProcessProtection.Disable();
                    }
                    else
                    {
                        LogText.AddNewLog(1, "Protection", $"Try to Enable ProcessProtection ...");
                        return Xdows.Protection.ProcessProtection.Enable(interceptCallBack);
                    }
                case 1:
                    if (FilesProtection.IsEnabled())
                    {
                        LogText.AddNewLog(1, "Protection", $"Try to Disable FilesProtection ...");
                        return Xdows.Protection.FilesProtection.Disable();
                    }
                    else
                    {
                        LogText.AddNewLog(1, "Protection", $"Try to Enable FilesProtection ...");
                        return Xdows.Protection.FilesProtection.Enable(interceptCallBack);
                    }
                case 4:
                    if (RegistryProtection.IsEnabled())
                    {
                        LogText.AddNewLog(1, "Protection", $"Try to Disable RegistryProtection ...");
                        return Xdows.Protection.RegistryProtection.Disable();
                    }
                    else
                    {
                        LogText.AddNewLog(1, "Protection", $"Try to Enable RegistryProtection ...");
                        return Xdows.Protection.RegistryProtection.Enable(interceptCallBack);
                    }
                default:
                    return false;
            }
        }
    }

    public static class Statistics
    {
        public static int ScansQuantity { get; set; } = 0;
        public static int VirusQuantity { get; set; } = 0;
    }
    /// <summary>
    /// 日志级别的枚举类型，定义了不同的日志级别。
    /// </summary>
    public enum LogLevel
    {
        DEBUG,  // 调试日志
        INFO,   // 信息日志
        WARN,   // 警告日志
        ERROR,  // 错误日志
        FATAL   // 致命错误日志
    }

    public static class LogText
    {
        #region 对外保持不变的接口
        public static event EventHandler? TextChanged;
        public static string Text => _hotCache.ToString();

        public static void ClearLog()
        {
            lock (_hotCache)
            {
                _hotCache.Clear();
                _hotLines = 0;
            }

            AddNewLog((int)LogLevel.INFO, "LogSystem", "Log is cleared");
        }
        #endregion

        #region 配置（可抽出去读 JSON）
        private const int HOT_MAX_LINES = 500;
        private const int HOT_MAX_BYTES = 80_000;
        private const int BATCH_SIZE = 100;
        private static readonly TimeSpan RetainAge = TimeSpan.FromDays(7);
        #endregion

        #region 路径 & 文件
        private static readonly string BaseFolder =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                         "Xdows-Security");

        private static string CurrentFilePath =>
            Path.Combine(BaseFolder, $"logs-{DateTime.Now:yyyy-MM-dd}.txt");
        #endregion

        #region 并发容器
        private static readonly StringBuilder _hotCache = new();
        private static readonly ConcurrentQueue<LogRow> _pending = new();
        private static int _hotLines;
        private static readonly SemaphoreSlim _signal = new(0, int.MaxValue);
        #endregion

        #region 启动后台写盘
        static LogText()
        {
            Directory.CreateDirectory(BaseFolder);
            _ = Task.Run(WritePump);
            AppDomain.CurrentDomain.UnhandledException += (_, e) =>
                AddNewLog((int)LogLevel.FATAL, "Unhandled", e.ExceptionObject.ToString()!);
        }
        #endregion

        #region 对外唯一写入口
        public static void AddNewLog(int level, string source, string info)
        {
            var row = new LogRow
            {
                Time = DateTime.Now,
                Level = level,
                Source = source,
                Text = info
            };

            _pending.Enqueue(row);
            _signal.Release();
            AppendToHotCache(row);
        }
        #endregion

        #region 热缓存（线程安全）
        private static void AppendToHotCache(LogRow row)
        {
            lock (_hotCache)
            {
                if (_hotLines >= HOT_MAX_LINES || _hotCache.Length >= HOT_MAX_BYTES)
                    TrimHotHead();

                _hotCache.AppendLine(FormatRow(row));
                _hotLines++;
            }

            RaiseChangedThrottled();
        }

        private static void TrimHotHead()
        {
            int cut = _hotCache.ToString().IndexOf('\n') + 1;
            if (cut > 0)
            {
                _hotCache.Remove(0, cut);
                _hotLines--;
            }
        }
        #endregion

        #region 事件节流
        private static Timer? _throttleTimer;
        private static void RaiseChangedThrottled()
        {
            if (Xdows_Security.MainWindow.NowPage != "Home") return;

            _throttleTimer?.Dispose();
            _throttleTimer = new Timer(_ => TextChanged?.Invoke(null, EventArgs.Empty),
                                       null, 100, Timeout.Infinite);
        }
        #endregion

        #region 后台写盘泵
        private static async Task WritePump()
        {
            var batch = new List<LogRow>(BATCH_SIZE);
            while (true)
            {
                await _signal.WaitAsync();
                while (_pending.TryDequeue(out var row)) batch.Add(row);
                if (batch.Count == 0) continue;

                try
                {
                    await File.AppendAllTextAsync(CurrentFilePath,
                        string.Join(Environment.NewLine, batch.ConvertAll(FormatRow)) +
                        Environment.NewLine);
                }
                catch
                {
                    var emergency = Path.Combine(BaseFolder, "emergency.log");
                    await File.AppendAllTextAsync(emergency,
                        string.Join(Environment.NewLine, batch.ConvertAll(FormatRow)) +
                        Environment.NewLine);
                }

                batch.Clear();
                RollIfNeeded();
            }
        }
        #endregion

        #region 工具
        private static string FormatRow(LogRow r) =>
            $"[{r.Time:yyyy-MM-dd HH:mm:ss}][{LevelToText(r.Level)}][{r.Source}][{Environment.CurrentManagedThreadId}]: {r.Text}";

        private static string LevelToText(int l) => l switch
        {
            0 => "DEBUG",
            1 => "INFO",
            2 => "WARN",
            3 => "ERROR",
            4 => "FATAL",
            _ => "UNKNOWN"
        };

        private static void RollIfNeeded()
        {
            var dir = new DirectoryInfo(BaseFolder);
            foreach (var f in dir.GetFiles("logs-*.txt"))
                if (DateTime.UtcNow - f.LastWriteTimeUtc > RetainAge)
                    f.Delete();
        }
        #endregion

        #region 内部行对象
        private record LogRow
        {
            public DateTime Time;
            public int Level;
            public string Source = "";
            public string Text = "";
        }
        #endregion
    }
    /// <summary>
    /// 应用程序的主入口类，负责启动和管理应用程序。
    /// </summary>
    public partial class App : Application
    {
        public static MainWindow? MainWindow { get; private set; } // 主窗口实例

        public App()
        {
            LogText.AddNewLog(1, "UI Interface", "Attempting to load the MainWindow...");
            this.InitializeComponent();
        }

        /// <summary>
        /// 应用程序启动时调用，处理启动参数。
        /// </summary>
        protected override async void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
            try
            {
                await InitializeLocalizer();
                InitializeMainWindow();
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(3, "App", $"Error in OnLaunched: {ex.Message}");
            }
        }
        private void InitializeMainWindow()
        {
            try
            {
                MainWindow = MainWindow ?? new MainWindow();
                MainWindow.Activate();
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(3, "App", $"Error initializing MainWindow: {ex.Message}");
            }
        }
        // 定义主题属性
        public static ElementTheme Theme { get; set; } = ElementTheme.Default;

        // 获取云API密钥
        public static string GetCzkCloudApiKey()
        {
            return string.Empty;
        }

        // 检查是否以管理员身份运行
        public static bool IsRunAsAdmin()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        private async Task InitializeLocalizer()
        {
            string stringsPath = Path.Combine(AppContext.BaseDirectory, "Strings");

            var settings = ApplicationData.Current.LocalSettings;
            string lastLang = settings.Values["AppLanguage"] as string ?? "en-US";

            ILocalizer localizer = await new LocalizerBuilder()
                .AddStringResourcesFolderForLanguageDictionaries(stringsPath)
                .SetOptions(o => o.DefaultLanguage = lastLang)
                .Build();
            // ApplicationLanguages.PrimaryLanguageOverride = "en-US";
            await localizer.SetLanguage(lastLang);
        }
        // Windows 版本获取
        public static string OsName => RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? (Environment.OSVersion.Version.Build >= 22000 ? "Windows 11" : "Windows 10")
            : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "macOS" : "Linux";

        public static string OsVersion => Environment.OSVersion.ToString();
    }
}
