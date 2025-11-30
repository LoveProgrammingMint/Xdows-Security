using Xdows.ScanEngine;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;
using static Xdows.Protection.CallBack;

namespace Xdows.Protection
{
    public static class ProcessProtection
    {
        // 感谢 XiaoWeiSecurity 对开源杀毒软件项目（特别是主动防御）的巨大贡献！！

        private static CancellationTokenSource? _cts = null;
        private static Task? _monitorTask = null;
        private static Xdows.ScanEngine.ScanEngine.SouXiaoEngineScan? SouXiaoEngine;
        public static bool Enable(InterceptCallBack toastCallBack)
        {
            SouXiaoEngine ??= new Xdows.ScanEngine.ScanEngine.SouXiaoEngineScan();
            SouXiaoEngine.Initialize();
            if (SouXiaoEngine == null)
            {
                return false;
            }
            if (IsEnabled())
                return true;
            try
            {
                _cts = new CancellationTokenSource();
                _monitorTask = Task.Run(() => MonitorNewProcessesLoop(toastCallBack, _cts.Token), _cts.Token);
                return true;
            }
            catch
            {
                return false;
            }
        }
        public static bool Disable()
        {
            if (!IsEnabled())
                return true;
            try
            {
                if (_cts is null || _monitorTask is null)
                    return true;
                try
                {
                    _cts.Cancel();
                    _monitorTask.Wait(2000);
                }
                catch { }
            }
            catch
            {
                return false;
            }
            finally
            {
                _cts?.Dispose();
                _cts = null;
                _monitorTask = null;
            }

            return true;
        }
        public static bool IsEnabled()
        {
            return _cts is { IsCancellationRequested: false };
        }

        private static readonly List<int> _oldPids = new List<int>();

        private static void MonitorNewProcessesLoop(InterceptCallBack interceptCallBack, CancellationToken token)
        {
            Debug.WriteLine("Protection Enabled");

            while (!token.IsCancellationRequested)
            {
                try
                {
                    var currentPids = GetProcessIdList();
                    if (_oldPids.Count == 0)
                    {
                        _oldPids.AddRange(currentPids);
                    }
                    else
                    {
                        var newPids = currentPids.Except(_oldPids).Distinct().ToList();

                        foreach (int pid in newPids)
                        {
                            string path = ProcessPidToPath(pid);
                            if (string.IsNullOrEmpty(path) || SouXiaoEngine == null)
                                continue;

                            bool isVirus = SouXiaoEngine.ScanFile(path).IsVirus;

                            if (isVirus)
                            {
                                bool Succeed = TryKillProcess(pid);

                                if (!Path.GetExtension(path).Equals(".virus", StringComparison.OrdinalIgnoreCase))
                                {
                                    try { File.Move(path, path + ".virus"); } catch { }
                                }
                                Task.Run(() =>
                                {
                                    interceptCallBack(Succeed, path, "Process");
                                });
                            }
                        }

                        _oldPids.Clear();
                        _oldPids.AddRange(currentPids);
                    }
                }
                catch
                {
                }
                try
                {
                    Task.Delay(10, token).Wait(token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }

            Debug.WriteLine("Protection Disabled");
        }

        private static List<int> GetProcessIdList()
        {
            const int maxCount = 512;
            int[] pids = new int[maxCount];
            int neededBytes;

            while (true)
            {
                if (!EnumProcesses(pids, pids.Length * 4, out neededBytes))
                    throw new Win32Exception();

                int returnedCount = neededBytes / 4;
                if (returnedCount < pids.Length)
                {
                    Array.Resize(ref pids, returnedCount);
                    break;
                }

                Array.Resize(ref pids, pids.Length + 128);
            }

            return pids.Where(id => id > 0).Distinct().ToList();
        }

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcesses(int[] lpidProcess, int cb, out int lpcbNeeded);

        private static string ProcessPidToPath(int pid)
        {
            const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

            IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProc == IntPtr.Zero)
                return string.Empty;

            try
            {
                var sb = new StringBuilder(1024);
                int capacity = sb.Capacity;
                if (QueryFullProcessImageName(hProc, 0, sb, ref capacity))
                    return sb.ToString();
            }
            finally
            {
                CloseHandle(hProc);
            }

            return string.Empty;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageName(
            IntPtr hProcess,
            int dwFlags,
            [Out] StringBuilder lpExeName,
            ref int lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        private static bool TryKillProcess(int pid)
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                proc.Kill();
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}