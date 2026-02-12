using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using System.Diagnostics;
using static Protection.CallBack;

namespace Protection
{
    public partial class ETW
    {
        public class RegistryProtection : IETWProtectionModel
        {
            private static readonly Lock lockObj = new();
            private static bool isRunning = false;
            public const string Name = "Registry";

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

                        monitoringSession = new TraceEventSession("Xdows-Security", null);
                        monitoringSession.EnableKernelProvider(
                            KernelTraceEventParser.Keywords.Registry
                        );

                        var parser = new KernelTraceEventParser(monitoringSession.Source);
                        parser.RegistryCreate += (data) => OnRegistryChange(data, interceptCallBack);

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

            private void OnRegistryChange(RegistryTraceData data, InterceptCallBack interceptCallBack)
            {
                try
                {
                    Debug.WriteLine(data.ProcessName);
                }
                catch { }
            }
        }
    }
}