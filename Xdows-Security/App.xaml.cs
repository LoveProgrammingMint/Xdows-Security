using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Windows.Storage;
using Xdows.Protection;
using static Xdows.Protection.CallBack;

namespace Xdows_Security
{
    public class AppInfo { 
        public static string AppName = "Xdows Security";
        public static string AppVersion = "4.10-Dev";
        public static string AppFeedback = "https://github.com/XTY64XTY12345/Xdows-Security/issues/new/choose";
        public static string AppWebsite = "https://xty64xty.netlify.app/";
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

    /// <summary>
    /// 日志管理类，负责收集并输出应用程序的日志信息。
    /// </summary>
    public static class LogText
    {
        private static StringBuilder _logText = new StringBuilder(); // 存储日志的 StringBuilder 对象
        private const int MAX_LOG_SIZE = 8000; // 最大日志大小
        private static readonly string LogFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Xdows-Security", "logs.txt"); // 日志文件路径

        public static event EventHandler? TextChanged; // 日志内容变更时的事件

        /// <summary>
        /// 获取当前日志的全部内容。
        /// </summary>
        public static string Text => _logText.ToString();

        /// <summary>
        /// 清空当前日志内容，并记录一条清空日志的操作。
        /// </summary>
        public static void ClearLog()
        {
            _logText.Clear();
            AddNewLog(1, "LogSystem", "Log is cleared");
        }

        /// <summary>
        /// 添加新的日志信息。
        /// </summary>
        /// <param name="level">日志级别</param>
        /// <param name="source">日志来源</param>
        /// <param name="info">日志内容</param>
        public static void AddNewLog(int level, string source, string info)
        {
            string currentTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string levelText = level switch
            {
                0 => "DEBUG",
                1 => "INFO",
                2 => "WARN",
                3 => "ERROR",
                4 => "FATAL",
                _ => "UNKNOWN",
            };
            string logEntry = $"[{currentTime}][{levelText}][{source}]: {info}{Environment.NewLine}";

            // 如果日志大小超过限制，清空日志
            if (_logText.Length + logEntry.Length > MAX_LOG_SIZE)
            {
                _logText.Clear();
            }

            _logText.Append(logEntry);

            // 如果当前页面是 Home 页面，触发 TextChanged 事件
            if (Xdows_Security.MainWindow.NowPage == "Home")
            {
                TextChanged?.Invoke(null, EventArgs.Empty);
            }
        }
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
            LogText.AddNewLog(1, "UI Interface", "尝试加载主窗口");
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
        protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
            try
            {
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
