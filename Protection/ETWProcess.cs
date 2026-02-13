using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using System.Diagnostics;
using TrustQuarantine;
using static Protection.CallBack;

namespace Protection
{
    public partial class ETW
    {
        // 进程防护模块
        public class ProcessProtection : IETWProtectionModel
        {
            private static readonly Lock lockObj = new();
            private static bool isRunning = false;
            public const string Name = "Process";
            string IETWProtectionModel.Name => Name;

            public bool Run(InterceptCallBack interceptCallBack)
            {
                lock (lockObj)
                {
                    if (isRunning)
                        return true;

                    try
                    {
                        SouXiaoEngine.Initialize();

                        isRunning = true;

                        monitoringSession = new TraceEventSession("Xdows-Security", null);
                        monitoringSession.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

                        var parser = new KernelTraceEventParser(monitoringSession.Source);
                        parser.ProcessStart += (data) => OnNewProcess(data, interceptCallBack);

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
            public bool Stop()
            {
                lock (lockObj)
                {
                    if (!isRunning)
                        return true;

                    try
                    {
                        monitoringSession?.Dispose();
                    }
                    finally
                    {
                        monitoringSession = null;
                        isRunning = false;
                    }
                    return true;
                }
            }
            public bool IsRun()
            {
                lock (lockObj)
                {
                    return isRunning;
                }
            }

            private static async void OnNewProcess(ProcessTraceData data, InterceptCallBack interceptCallBack)
            {
                try
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

                    var (isVirus, result) = SouXiaoEngine.ScanFile(path);
                    if (!isVirus)
                        return;

                    try
                    {
                        using var proc = Process.GetProcessById(data.ProcessID);
                        proc.Kill();
                        _ = QuarantineManager.AddToQuarantine(path, result);
                        interceptCallBack(true, path, Name);

                    }
                    catch
                    {
                        interceptCallBack(false, path, Name);
                    }
                }
                catch { }
            }
        }
    }
}