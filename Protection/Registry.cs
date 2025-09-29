using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

namespace Xdows.Protection
{
    public static class RegistryProtection
    {
        // 回调委托
        public static CallBack.InterceptCallBack InterceptCallback;

        // 监控状态
        private static bool _isEnabled = false;
        private static IntPtr _hRegistryKey = IntPtr.Zero;
        private static Thread _monitorThread;
        private static CancellationTokenSource _cancellationTokenSource;

        // Windows API 常量
        private const uint KEY_NOTIFY = 0x0010;
        private const uint REG_NOTIFY_CHANGE_LAST_SET = 0x00000004;
        private const uint REG_NOTIFY_CHANGE_NAME = 0x00000001;
        private const uint REG_NOTIFY_CHANGE_ATTRIBUTES = 0x00000002;
        private const uint REG_NOTIFY_CHANGE_SECURITY = 0x00000008;
        private const uint ERROR_SUCCESS = 0;
        private const uint ERROR_NO_MORE_ITEMS = 259;

        // Windows API 函数
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegOpenKeyEx(
            IntPtr hKey,
            string subKey,
            uint ulOptions,
            uint samDesired,
            out IntPtr hkResult);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegCloseKey(IntPtr hKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegNotifyChangeKeyValue(
            IntPtr hKey,
            bool bWatchSubtree,
            uint dwNotifyFilter,
            IntPtr hEvent,
            bool fAsynchronous);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateEvent(
            IntPtr lpEventAttributes,
            bool bManualReset,
            bool bInitialState,
            string lpName);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        // 注册表根键常量
        private static readonly IntPtr HKEY_LOCAL_MACHINE = (IntPtr)0x80000002;
        private static readonly IntPtr HKEY_CURRENT_USER = (IntPtr)0x80000001;
        private static readonly IntPtr HKEY_CLASSES_ROOT = (IntPtr)0x80000000;
        private static readonly IntPtr HKEY_USERS = (IntPtr)0x80000003;
        private static readonly IntPtr HKEY_CURRENT_CONFIG = (IntPtr)0x80000005;

        // 要监控的注册表路径
        private static readonly List<string> _monitoredPaths = new List<string>
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
            @"SYSTEM\CurrentControlSet\Services",
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        };

        /// <summary>
        /// 启用注册表保护监控
        /// </summary>
        /// <param name="cb">回调函数</param>
        /// <returns>是否启用成功</returns>
        public static bool Enable(CallBack.InterceptCallBack cb)
        {
            if (_isEnabled)
            {
                Console.WriteLine("注册表监控已经启用");
                return false;
            }

            if (cb == null)
            {
                Console.WriteLine("回调函数不能为null");
                return false;
            }

            InterceptCallback = cb;
            _isEnabled = true;
            _cancellationTokenSource = new CancellationTokenSource();

            // 启动监控线程
            _monitorThread = new Thread(MonitorRegistryChanges);
            _monitorThread.IsBackground = true;
            _monitorThread.Start();

            Console.WriteLine("注册表监控已启用");
            return true;
        }

        /// <summary>
        /// 禁用注册表保护监控
        /// </summary>
        /// <returns>是否禁用成功</returns>
        public static bool Disable()
        {
            if (!_isEnabled)
            {
                Console.WriteLine("注册表监控未启用");
                return false;
            }

            _isEnabled = false;
            _cancellationTokenSource?.Cancel();

            // 等待监控线程结束
            if (_monitorThread != null && _monitorThread.IsAlive)
            {
                _monitorThread.Join(3000);
                if (_monitorThread.IsAlive)
                {
                    try { _monitorThread.Abort(); } catch { }
                }
            }

            // 关闭注册表句柄
            if (_hRegistryKey != IntPtr.Zero)
            {
                RegCloseKey(_hRegistryKey);
                _hRegistryKey = IntPtr.Zero;
            }

            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;

            Console.WriteLine("注册表监控已禁用");
            return true;
        }

        /// <summary>
        /// 检查注册表监控是否启用
        /// </summary>
        /// <returns>监控状态</returns>
        public static bool IsEnabled()
        {
            return _isEnabled;
        }

        /// <summary>
        /// 监控注册表变化的线程函数
        /// </summary>
        private static void MonitorRegistryChanges()
        {
            try
            {
                while (_isEnabled && !_cancellationTokenSource.Token.IsCancellationRequested)
                {
                    foreach (var path in _monitoredPaths)
                    {
                        if (!_isEnabled) break;

                        try
                        {
                            MonitorSingleRegistryKey(HKEY_LOCAL_MACHINE, path);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"监控注册表路径 {path} 时出错: {ex.Message}");
                        }

                        // 添加短暂延迟，避免CPU占用过高
                        Thread.Sleep(100);
                    }

                    // 监控HKEY_CURRENT_USER下的关键路径
                    try
                    {
                        MonitorSingleRegistryKey(HKEY_CURRENT_USER, @"Software\Microsoft\Windows\CurrentVersion\Run");
                        MonitorSingleRegistryKey(HKEY_CURRENT_USER, @"Software\Microsoft\Windows\CurrentVersion\RunOnce");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"监控HKEY_CURRENT_USER时出错: {ex.Message}");
                    }

                    Thread.Sleep(1000); // 主循环延迟
                }
            }
            catch (ThreadAbortException)
            {
                // 线程被中止，正常退出
            }
            catch (Exception ex)
            {
                Console.WriteLine($"监控线程发生错误: {ex.Message}");
            }
        }

        /// <summary>
        /// 监控单个注册表键
        /// </summary>
        private static void MonitorSingleRegistryKey(IntPtr hKey, string subKey)
        {
            IntPtr hSubKey = IntPtr.Zero;
            IntPtr hEvent = IntPtr.Zero;

            try
            {
                // 打开注册表键
                int result = RegOpenKeyEx(hKey, subKey, 0, KEY_NOTIFY, out hSubKey);
                if (result != ERROR_SUCCESS)
                {
                    // 如果键不存在，忽略错误
                    if (result == 2) // ERROR_FILE_NOT_FOUND
                        return;

                    throw new Win32Exception(result);
                }

                // 创建事件对象
                hEvent = CreateEvent(IntPtr.Zero, true, false, null);
                if (hEvent == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // 设置注册表变更通知
                result = RegNotifyChangeKeyValue(
                    hSubKey,
                    true, // 监控子键
                    REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME |
                    REG_NOTIFY_CHANGE_ATTRIBUTES | REG_NOTIFY_CHANGE_SECURITY,
                    hEvent,
                    true); // 异步方式

                if (result != ERROR_SUCCESS)
                {
                    throw new Win32Exception(result);
                }

                // 等待事件触发（最多等待5秒）
                uint waitResult = WaitForSingleObject(hEvent, 5000);

                if (waitResult == 0) // WAIT_OBJECT_0
                {
                    // 注册表发生变化
                    string fullPath = GetRootKeyName(hKey) + "\\" + subKey;
                    OnRegistryChanged(fullPath);
                }
            }
            finally
            {
                if (hSubKey != IntPtr.Zero)
                {
                    RegCloseKey(hSubKey);
                }
                if (hEvent != IntPtr.Zero)
                {
                    CloseHandle(hEvent);
                }
            }
        }

        /// <summary>
        /// 获取根键名称
        /// </summary>
        private static string GetRootKeyName(IntPtr hKey)
        {
            if (hKey == HKEY_LOCAL_MACHINE) return "HKEY_LOCAL_MACHINE";
            if (hKey == HKEY_CURRENT_USER) return "HKEY_CURRENT_USER";
            if (hKey == HKEY_CLASSES_ROOT) return "HKEY_CLASSES_ROOT";
            if (hKey == HKEY_USERS) return "HKEY_USERS";
            if (hKey == HKEY_CURRENT_CONFIG) return "HKEY_CURRENT_CONFIG";
            return "UNKNOWN";
        }

        /// <summary>
        /// 注册表变化事件处理
        /// </summary>
        private static void OnRegistryChanged(string registryPath)
        {
            try
            {
                Console.WriteLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] 检测到注册表修改: {registryPath}");

                // 调用回调函数
                InterceptCallback?.Invoke(true, registryPath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"处理注册表变化时出错: {ex.Message}");
                InterceptCallback?.Invoke(false, registryPath);
            }
        }
    }
}
