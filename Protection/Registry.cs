using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Analysis;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using static Xdows.Protection.CallBack;

namespace Xdows.Protection
{
    public static class RegistryProtection
    {
        private static TraceEventSession _session;
        private static Task _processingTask;
        private static CancellationTokenSource _cts;
        private static InterceptCallBack _callback;

        private static readonly ConcurrentQueue<string> _queue = new();

        public static bool Enable(InterceptCallBack cb)
        {
            if (_session != null) return false;
            if (!(TraceEventSession.IsElevated() ?? false)) return false;

            _callback = cb;
            _cts = new CancellationTokenSource();

            try
            {
                _session = new TraceEventSession("NT Kernel Logger");

                _session.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.Registry,
                    KernelTraceEventParser.Keywords.None);

                _processingTask = Task.Run(() => ProcessingLoop(_cts.Token), _cts.Token);
                _ = Task.Run(() => Consumer(_cts.Token), _cts.Token);

                return true;
            }
            catch
            {
                Disable();
                throw;
            }
        }

        private static readonly ThreadLocal<bool> _inCallback = new();
        private static void ProcessingLoop(CancellationToken token)
        {
            int myPid = Process.GetCurrentProcess().Id;

            _session.Source.Kernel.AddCallbackForEvents<RegistryTraceData>(data =>
            {
                if (_inCallback.Value) return;
                _inCallback.Value = true;
                try
                {
                    if (data.ProcessID == Process.GetCurrentProcess().Id & data.KeyName == String.Empty) return;

                    var msg = $"[REG] PID:{data.ProcessID} {data.OpcodeName} {data.KeyName}";
                    if (data.KeyName.Contains("CurrentVersion\\Run") &
                        data.KeyName.Contains("Policies")
                    )
                    {
                        Console.WriteLine(data.KeyName);
                        Console.WriteLine(data.ProcessID);
                    }
                }
                finally
                {
                    _inCallback.Value = false;
                }
            });

            _session.Source.Process();
        }

        private static async Task Consumer(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested || !_queue.IsEmpty)
                {
                    if (_queue.TryDequeue(out var msg))
                    {
                        _callback?.Invoke(true, msg);
                    }
                    else
                    {
                        await Task.Delay(50, token);
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Debug.WriteLine($"RegistryProtection consumer error: {ex}");
            }
        }

        public static bool Disable()
        {
            if (_session == null) return false;

            _cts?.Cancel();

            var psi = new ProcessStartInfo
            {
                FileName = "logman",
                Arguments = "stop \"NT Kernel Logger\" -ets",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var p = Process.Start(psi);
            p?.WaitForExit();

            try { _session?.Dispose(); }
            catch { }
            _cts?.Dispose();
            _cts = null;
            _session = null;
            _processingTask = null;

            return true;
        }

        public static bool IsEnabled() => _session != null;
    }
}