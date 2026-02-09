using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using System.Diagnostics;
using TrustQuarantine;
using static Protection.CallBack;

namespace Protection
{
    public class ETW
    {
        public delegate void MonitoringCallback(ProcessTraceData data, InterceptCallBack interceptCallBack);

        private static readonly ScanEngine.ScanEngine.SouXiaoEngineScan SouXiaoEngine = new();
        private static TraceEventSession? monitoringSession;
        private static bool isRunning = false;
        private static readonly object lockObj = new();

        // 进程防护模块
        public class ProcessProtection
        {
            public static bool Run(InterceptCallBack interceptCallBack)
            {
                lock (lockObj)
                {
                    if (isRunning)
                        return true;

                    try
                    {
                        SouXiaoEngine.Initialize();

                        monitoringSession = new TraceEventSession("Xdows-Security", null);
                        monitoringSession.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

                        var parser = new KernelTraceEventParser(monitoringSession.Source);
                        parser.ProcessStart += (data) => OnNewProcess(data, interceptCallBack);

                        isRunning = true;
                        _ = Task.Run(() =>
                        {
                            try
                            {
                                monitoringSession.Source.Process();
                            }
                            finally
                            {
                                lock (lockObj)
                                {
                                    isRunning = false;
                                }
                            }
                        });

                        return true;
                    }
                    catch
                    {
                        monitoringSession?.Dispose();
                        monitoringSession = null;
                        return false;
                    }
                }
            }
            public static void Stop()
            {
                lock (lockObj)
                {
                    if (!isRunning)
                        return;

                    try
                    {
                        monitoringSession?.Dispose();
                    }
                    finally
                    {
                        monitoringSession = null;
                        isRunning = false;
                    }
                }
            }
            public static bool IsRun()
            {
                lock (lockObj)
                {
                    return isRunning;
                }
            }

            private static void OnNewProcess(ProcessTraceData data, InterceptCallBack interceptCallBack)
            {
                if (data.ProcessID is 0 or 4)
                    return;

                string? path = null;
                try
                {
                    using var process = Process.GetProcessById(data.ProcessID);
                    path = process.MainModule?.FileName;
                }
                catch
                {
                    return;
                }

                if (string.IsNullOrEmpty(path) || TrustManager.IsPathTrusted(path))
                    return;

                Debug.WriteLine($"[ETW] 检测到新进程: {path}");

                var (isVirus, result) = SouXiaoEngine.ScanFile(path);
                if (!isVirus)
                    return;

                bool success = false;
                try
                {
                    using var proc = Process.GetProcessById(data.ProcessID);
                    proc.Kill();
                    success = true;
                }
                catch
                {
                    success = false;
                }

                _ = QuarantineManager.AddToQuarantine(path, result);
                interceptCallBack(success, path, "Process");
            }
        }
    }
}