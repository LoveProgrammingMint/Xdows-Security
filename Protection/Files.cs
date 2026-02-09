using TrustQuarantine;
using static Protection.CallBack;
namespace Protection
{
    public class LegacyFilesProtection : IProtectionModel
    {
        private static FileSystemWatcher[]? _watchers;
        private static InterceptCallBack? _toastCallBack;
        private static Thread? _monitorThread;
        private static bool _isMonitoring = false;
        private static ScanEngine.ScanEngine.SouXiaoEngineScan? SouXiaoEngine;
        public string Name => "FilesProtection";
        public bool Enable(InterceptCallBack toastCallBack)
        {
            SouXiaoEngine ??= new ScanEngine.ScanEngine.SouXiaoEngineScan();
            SouXiaoEngine.Initialize();

            if (_isMonitoring || SouXiaoEngine == null)
            {
                return false;
            }

            _isMonitoring = true;
            _toastCallBack = toastCallBack;
            _monitorThread = new Thread(StartMonitoring)
            {
                IsBackground = true
            };
            _monitorThread.Start();

            return true;
        }

        public bool Disable()
        {
            if (!_isMonitoring)
            {
                return false;
            }

            _isMonitoring = false;
            if (_watchers == null)
            {
                return false;
            }
            foreach (var watcher in _watchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch { return false; }
            }
            if (_monitorThread != null && _monitorThread.IsAlive)
                _monitorThread.Join();

            return true;
        }

        public bool IsEnabled()
        {
            try { return _isMonitoring; } catch { return false; }
        }

        private static void StartMonitoring()
        {
            string[] drives = Directory.GetLogicalDrives();
            _watchers = new FileSystemWatcher[drives.Length];

            for (int i = 0; i < drives.Length; i++)
            {
                try
                {
                    _watchers[i] = new FileSystemWatcher
                    {
                        Path = drives[i],
                        NotifyFilter = NotifyFilters.LastAccess
                                       | NotifyFilters.LastWrite
                                       | NotifyFilters.FileName
                                       | NotifyFilters.DirectoryName,
                        IncludeSubdirectories = true,
                        Filter = "*.*"
                    };

                    _watchers[i].Changed += OnChanged;
                    _watchers[i].Created += OnChanged;
                    // _watchers[i].Deleted += OnChanged;
                    _watchers[i].Renamed += OnChanged;
                    _watchers[i].EnableRaisingEvents = true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error setting up watcher for {drives[i]}: {ex.Message}");
                }
            }

            while (_isMonitoring)
            {
                Thread.Sleep(1000);
            }
        }
        private static bool IsFileAccessible(string path)
        {
            try
            {
                if (Directory.Exists(path))
                    return false;
                if (!File.Exists(path))
                    return false;
                using var _ = File.Open(path, FileMode.Open, FileAccess.Read,
                                         FileShare.ReadWrite);
                return true;
            }
            catch
            {
                return false;
            }
        }
        private static async void OnChanged(object sender, FileSystemEventArgs e)
        {
            try
            {
                if (
                    e.FullPath.Contains("\\AppData\\Local\\Temp", StringComparison.OrdinalIgnoreCase) ||
                    !IsFileAccessible(e.FullPath) ||
                    SouXiaoEngine == null
                )
                {
                    return;
                }

                if (TrustManager.IsPathTrusted(e.FullPath))
                {
                    return;
                }

                var (IsVirus, Result) = SouXiaoEngine.ScanFile(e.FullPath);
                if (IsVirus)
                {
                    try
                    {
                        bool success = await QuarantineManager.AddToQuarantine(e.FullPath, Result);

                        _ = Task.Run(() =>
                        {
                            _toastCallBack?.Invoke(success, e.FullPath, "Process");
                        });
                    }
                    catch
                    {
                        _ = Task.Run(() =>
                        {
                            _toastCallBack?.Invoke(false, e.FullPath, "Process");
                        });
                    }

                }
            }
            catch { }
        }
    }
}