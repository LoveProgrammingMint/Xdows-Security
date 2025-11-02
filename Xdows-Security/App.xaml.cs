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
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Windows.Globalization;
using WinUI3Localizer;
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

        public static InterceptCallBack interceptCallBack = (bool isSucceed, string path) =>
        {
            LogText.AddNewLog(2, "Protection", isSucceed
                ? $"InterceptProcess：{Path.GetFileName(path)}"
                : $"Cannot InterceptProcess：{Path.GetFileName(path)}");
            string content = isSucceed ? "已发现威胁" : "无法处理威胁";
            content = $"{AppInfo.AppName} {content}.{Environment.NewLine}相关数据：{Path.GetFileName(path)}{Environment.NewLine}单击此通知以查看详细信息";
            Notifications.ShowNotification("发现威胁", content, path);
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

    public static class Notifications
    {
        /// <summary>
        /// 显示通知
        /// </summary>
        public static void ShowNotification(string title, string content, string path)
        {
            var builder = new AppNotificationBuilder()
                .AddText(title)
                .AddText(content)
                .AddArgument("action", "openIntercept")
                .AddArgument("path", path);

            AppNotification notification = builder.BuildNotification();
            try
            {
                var markerDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Xdows-Security");
                Directory.CreateDirectory(markerDir);
                var markerPath = Path.Combine(markerDir, "lastNotification.json");
                var markerObj = new
                {
                    action = "openIntercept",
                    path = path,
                    time = DateTime.UtcNow.ToString("o"),
                    content = content
                };
                File.WriteAllText(markerPath, JsonSerializer.Serialize(markerObj));
            }
            catch { }
            AppNotificationManager.Default.Show(notification);
        }
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
        private static int _mainWindowCreating = 0; // 标志位，防止多个线程同时创建 MainWindow
        public static MainWindow? MainWindow { get; private set; } // 主窗口实例

        public App()
        {
            // 在启动时尝试初始化通知管理器
            LogText.AddNewLog(1, "UI Interface", "Attempting to load the MainWindow...");
            try
            {
                InitializeAppNotificationManager();
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(3, "UI Interface", $"Error initializing notifications: {ex.Message}");
            }
        }

        /// <summary>
        /// 初始化应用的通知管理器。
        /// </summary>
        private void InitializeAppNotificationManager()
        {
            AppNotificationManager mgr = AppNotificationManager.Default;
            mgr.NotificationInvoked += OnAppNotificationInvoked;
        }

        /// <summary>
        /// 处理通知激活事件。
        /// </summary>
        private async void OnAppNotificationInvoked(object? sender, AppNotificationActivatedEventArgs e)
        {
            try
            {
                var argsDict = e.Arguments as IDictionary<string, string>;
                if (argsDict != null && argsDict.TryGetValue("action", out var action) && action == "openIntercept")
                {
                    string interceptedPath = argsDict.TryGetValue("path", out var path) ? path : string.Empty;
                    LogText.AddNewLog(1, "Notifications", $"Notification invoked with action={action}, path={interceptedPath}");
                    await HandleNotification(invokedAction: action, interceptedPath: interceptedPath);
                }
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(3, "Notifications", $"Error processing notification: {ex.Message}");
            }
        }

        /// <summary>
        /// 处理通知中的具体操作。
        /// </summary>
        private async Task HandleNotification(string invokedAction, string interceptedPath)
        {
            if (MainWindow == null)
            {
                if (System.Threading.Interlocked.CompareExchange(ref _mainWindowCreating, 1, 0) == 0)
                {
                    try
                    {
                        MainWindow = new MainWindow();
                    }
                    catch (Exception ex)
                    {
                        LogText.AddNewLog(3, "MainWindow", $"Failed to create MainWindow: {ex.Message}");
                    }
                    finally
                    {
                        System.Threading.Interlocked.Exchange(ref _mainWindowCreating, 0);
                    }
                }
                else
                {
                    await Task.Delay(100); // Wait before trying again
                }
            }

            if (MainWindow != null)
            {
                var dq = MainWindow.DispatcherQueue;
                dq?.TryEnqueue(() =>
                {
                    try
                    {
                        MainWindow.Activate();
                        InterceptWindow.ShowOrActivate(interceptedPath);
                    }
                    catch (Exception ex)
                    {
                        LogText.AddNewLog(3, "MainWindow", $"Failed to activate MainWindow or InterceptWindow: {ex.Message}");
                    }
                });
            }
        }

        /// <summary>
        /// 应用程序启动时调用，处理启动参数。
        /// </summary>
        protected override async void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
            try
            {
                await InitializeLocalizer();
                if (args.Arguments.Contains("openIntercept"))
                {
                    HandleInterceptLaunch(args);
                }
                else
                {
                    InitializeMainWindow();
                }
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(3, "App", $"Error in OnLaunched: {ex.Message}");
            }
        }

        /// <summary>
        /// 处理拦截启动的参数。
        /// </summary>
        private void HandleInterceptLaunch(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
            try
            {
                MainWindow?.Activate();
                string interceptedPath = TryConsumeNotificationMarker().path;
                InterceptWindow.ShowOrActivate(interceptedPath);
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(3, "App", $"Error launching intercept: {ex.Message}");
            }
        }

        /// <summary>
        /// 初始化主窗口并显示。
        /// </summary>
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

        /// <summary>
        /// 尝试消费通知标记，获取拦截的路径。
        /// </summary>
        private (bool exists, string path) TryConsumeNotificationMarker()
        {
            try
            {
                var markerDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Xdows-Security");
                var markerPath = Path.Combine(markerDir, "lastNotification.json");
                if (!File.Exists(markerPath)) return (false, string.Empty);

                var txt = File.ReadAllText(markerPath);
                var doc = JsonDocument.Parse(txt);
                string path = string.Empty;
                bool hasAction = false;

                if (doc.RootElement.TryGetProperty("action", out var action) && action.GetString() == "openIntercept")
                {
                    hasAction = true;
                }

                if (doc.RootElement.TryGetProperty("path", out var pathElement))
                {
                    path = pathElement.GetString() ?? string.Empty;
                }

                // 删除标记文件以防重复触发
                try { File.Delete(markerPath); } catch { }

                return (hasAction, path);
            }
            catch { }
            return (false, string.Empty);
        }
        // 定义主题属性
        public static ElementTheme Theme { get; set; } = ElementTheme.Default;

        // 获取云API密钥
        public static string GetCzkCloudApiKey()
        {
            return string.Empty;  // 实际的 API 密钥
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
        // 重新启动应用程序
        public static void RestartApplication()
        {
            try
            {
                var appPath = Environment.ProcessPath;
                Process.Start(new ProcessStartInfo
                {
                    FileName = appPath,
                    UseShellExecute = true
                });
                Application.Current.Exit();
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(3, "App", $"Failed to restart application: {ex.Message}");
            }
        }

        // 检查 Windows 版本
        public static bool CheckWindowsVersion()
        {
            var version = Environment.OSVersion.Version;
            if (version.Major == 10 && version.Build >= 22000)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
