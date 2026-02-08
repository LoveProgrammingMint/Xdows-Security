using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System.Diagnostics;
using TrustQuarantine;

namespace Protection
{
    public class ETW
    {
        public delegate void MonitoringCallback(Microsoft.Diagnostics.Tracing.Parsers.Kernel.ProcessTraceData data);
        private static ScanEngine.ScanEngine.SouXiaoEngineScan? SouXiaoEngine;

        // 这里是进程防护部分awa（By Shiyi）
        public class ProcessProtection
        {
            // Run!!!(By Shiyi)
            public bool Run()
            {
                SouXiaoEngine ??= new ScanEngine.ScanEngine.SouXiaoEngineScan();
                SouXiaoEngine.Initialize();
                if (SouXiaoEngine == null)
                {
                    return false;
                }
                ProcessMonitoring(OnNewProcess);
                return true; //其实我也不知道有没有成功（By Shiyi）
            }
            static void OnNewProcess(Microsoft.Diagnostics.Tracing.Parsers.Kernel.ProcessTraceData data)
            {
                string? path;
                try { path = Process.GetProcessById(data.ProcessID).MainModule?.FileName; } catch { return; }

                if (string.IsNullOrEmpty(path) || SouXiaoEngine == null)
                    return;
                // 检查文件是否在信任区中
                if (TrustManager.IsPathTrusted(path))
                    return;
                var (IsVirus, Result) = SouXiaoEngine.ScanFile(path);
                if (IsVirus)
                {
                    Console.WriteLine($"检测到恶意进程: {data.ProcessName} (PID={data.ProcessID}) - {Result}");
                    try
                    {
                        Process.GetProcessById(data.ProcessID).Kill();

                        _ = QuarantineManager.AddToQuarantine(path, Result);
                        Console.WriteLine($"已终止恶意进程: {data.ProcessName} (PID={data.ProcessID})");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"无法终止进程: {data.ProcessName} (PID={data.ProcessID}) - {ex.Message}");
                    }
                }
            }
            public static void ProcessMonitoring(MonitoringCallback callback)
            {
                using var session = new TraceEventSession("Xdows-Security", null);
                session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

                var parser = new KernelTraceEventParser(session.Source);

                parser.ProcessStart += (data) =>
                    callback.Invoke(data);

                session.Source.Process();
            }
        }
    }
}
