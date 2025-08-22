using SouXiaoEngine;
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
using static Xdows.Protection.ProcessProtection;

namespace Xdows.Protection
{
    public static class ProcessProtection
    {
        // 感谢 XiaoWeiSecurity 对开源杀毒软件项目（特别是主动防御）的巨大贡献！！
        public delegate void ToastCallBack(string title,string content);
        public static bool EnableProtection(ToastCallBack toastCallBack)
        {
            try
            {
                _ = Task.Run(() => MonitorNewProcessesLoop(toastCallBack));
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static readonly List<int> _oldPids = new List<int>();
        private static void MonitorNewProcessesLoop(ToastCallBack toastCallBack)
        {
            string ModelPath = AppDomain.CurrentDomain.BaseDirectory + "model.onnx";
            MalwareScanner SouXiaoEngine = new MalwareScanner(ModelPath);
            Debug.WriteLine("Protection Enabled");
            while (true)
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
                            if (string.IsNullOrEmpty(path))
                                continue;


                            string Result = SouXiaoEngine.ScanFile(path) ? SouXiaoEngine.GetReturn() : string.Empty;

                            bool isVirus = Result == string.Empty ? false : true;


                            if (isVirus)
                            {
                                bool canKill = TryKillProcess(pid);

                                string title = "发现威胁";
                                string body = canKill
                                    ? $"Xdows Security 已发现威胁.{Environment.NewLine}相关进程：{Path.GetFileName(path)}"
                                    : $"Xdows Security 无法处理威胁.{Environment.NewLine}相关进程：{Path.GetFileName(path)}";
                                toastCallBack(title, body);
                            }
                        }

                        // 更新旧列表
                        _oldPids.Clear();
                        _oldPids.AddRange(currentPids);
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("MonitorNewProcessesLoop error: " + ex);
                }

                Thread.Sleep(10);
            }
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

                // 扩容
                Array.Resize(ref pids, pids.Length + 128);
            }

            return pids.Where(id => id > 0).Distinct().ToList(); // 简易去重
        }

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcesses(int[] lpidProcess, int cb, out int lpcbNeeded);

        private static string ProcessPidToPath(int pid)
        {
            const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

            IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProc == IntPtr.Zero)
                return null;

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

            return null;
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