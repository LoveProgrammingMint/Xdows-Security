using System;
using Xdows.ScanEngine;
using System.IO;
using System.Linq;
using System.Threading;
using static Xdows.Protection.CallBack;

namespace Xdows.Protection
{
    public static class FilesProtection
    {
        private static FileSystemWatcher[]? _watchers;
        private static InterceptCallBack? _toastCallBack;
        private static Thread? _monitorThread;
        private static bool _isMonitoring = false;
        private static Xdows.ScanEngine.ScanEngine.SouXiaoEngineScan? SouXiaoEngine;
        public static bool Enable(InterceptCallBack toastCallBack)
        {
            SouXiaoEngine ??= new Xdows.ScanEngine.ScanEngine.SouXiaoEngineScan();
            SouXiaoEngine.Initialize();
            if (_isMonitoring || SouXiaoEngine == null)
            {
                return false;
            }
            
            _isMonitoring = true;
            _toastCallBack = toastCallBack;
            _monitorThread = new Thread(StartMonitoring);
            _monitorThread.IsBackground = true;
            _monitorThread.Start();

            return true;
        }

        public static bool Disable()
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
                try {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch { return false; }
            }
            if (_monitorThread != null && _monitorThread.IsAlive)
                _monitorThread.Join();

            return true;
        }

        public static bool IsEnabled()
        {
            try {return _isMonitoring;} catch { return false; }
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
        static bool IsFileAccessible(string path)
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
        private static void OnChanged(object sender, FileSystemEventArgs e)
        {
            try
            {
                if (
                    e.FullPath.Contains("\\AppData\\Local\\Temp", StringComparison.OrdinalIgnoreCase) ||
                    Path.GetExtension(e.FullPath).Equals(".virus", StringComparison.OrdinalIgnoreCase) ||
                    !IsFileAccessible(e.FullPath) ||
                    SouXiaoEngine == null
                )
                {
                    return;
                }
                bool isVirus = false;
                isVirus = SouXiaoEngine.ScanFile(e.FullPath).IsVirus;
                if (isVirus)
                {
                    try
                    {
                        File.Move(e.FullPath, e.FullPath + ".virus");
                        Task.Run(() =>
                        {
                            _toastCallBack?.Invoke(true, e.FullPath);
                        });
                    }
                    catch
                    {
                        Task.Run(() =>
                        {
                            _toastCallBack?.Invoke(false, e.FullPath);
                        });
                    }

                }
            }
            catch { }
        }
    }
}