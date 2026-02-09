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
        internal static TraceEventSession? monitoringSession;

        public class FilesProtection
        {
            private static readonly Lock lockObj = new();
            private static bool isRunning = false;

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
                        monitoringSession.EnableKernelProvider(
                            KernelTraceEventParser.Keywords.FileIO |
                            KernelTraceEventParser.Keywords.FileIOInit,
                            KernelTraceEventParser.Keywords.None
                        );

                        var parser = new KernelTraceEventParser(monitoringSession.Source);
                        parser.FileIOCreate += (data) => _ = OnFileCreate(data, interceptCallBack);

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

            private static async Task OnFileCreate(FileIOCreateTraceData data, InterceptCallBack interceptCallBack)
            {
                if (data.ProcessID is 0 or 4)
                    return;

                string? filePath = data.FileName;
                if (string.IsNullOrEmpty(filePath) ||
                    !Path.Exists(filePath) ||
                    Path.EndsInDirectorySeparator(filePath) ||
                    filePath.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase) ||
                    filePath.Length > 32767)
                    return;

                if (!IsSuspiciousExtension(filePath))
                    return;

                string? creatorProcessPath = null;
                try
                {
                    using var process = Process.GetProcessById(data.ProcessID);
                    creatorProcessPath = process.MainModule?.FileName;
                }
                catch
                {
                    return;
                }

                if (!string.IsNullOrEmpty(creatorProcessPath) && TrustManager.IsPathTrusted(creatorProcessPath))
                    return;

                HandleCreatedFile(filePath, data.ProcessID, interceptCallBack);
            }

            private static void HandleCreatedFile(string filePath, int creatorProcessId, InterceptCallBack interceptCallBack)
            {
                var (isFileVirus, fileResult) = SouXiaoEngine.ScanFile(filePath);
                if (isFileVirus)
                {
                    TerminateProcessByPath(filePath);
                    _ = QuarantineManager.AddToQuarantine(filePath, fileResult);
                    interceptCallBack(true, filePath, "Files");
                }

                string? creatorPath = null;
                try
                {
                    using var proc = Process.GetProcessById(creatorProcessId);
                    creatorPath = proc.MainModule?.FileName;
                }
                catch
                {
                    return;
                }

                if (string.IsNullOrEmpty(creatorPath))
                    return;

                var (isProcessVirus, processResult) = SouXiaoEngine.ScanFile(creatorPath);
                if (isProcessVirus)
                {
                    try
                    {
                        using var proc = Process.GetProcessById(creatorProcessId);
                        proc.Kill();
                    }
                    catch
                    {
                    }

                    _ = QuarantineManager.AddToQuarantine(creatorPath, processResult);
                    interceptCallBack(true, creatorPath, "Files");
                }
            }

            private static void TerminateProcessByPath(string filePath)
            {
                try
                {
                    var processes = Process.GetProcesses();
                    foreach (var proc in processes)
                    {
                        try
                        {
                            if (proc.MainModule?.FileName?.Equals(filePath, StringComparison.OrdinalIgnoreCase) == true)
                            {
                                proc.Kill();
                            }
                        }
                        catch
                        {
                        }
                    }
                }
                catch
                {
                }
            }

            private static bool IsSuspiciousExtension(string filePath)
            {
                var ext = Path.GetExtension(filePath).ToLowerInvariant();
                return ext is ".exe" or ".dll" or ".sys" or ".scr" or ".bat"
                    or ".cmd" or ".ps1" or ".vbs" or ".js" or ".jse"
                    or ".wsf" or ".msi" or ".msp" or ".cab" or ".zip"
                    or ".rar" or ".7z" or ".iso" or ".doc" or ".docx"
                    or ".xls" or ".xlsx" or ".ppt" or ".pptx" or ".pdf";
            }
        }
    }
}