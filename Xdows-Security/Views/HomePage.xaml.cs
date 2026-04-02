using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.Windows.Storage.Pickers;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Windows.ApplicationModel.DataTransfer;
using WinRT.Interop;
using WinUI3Localizer;

namespace Xdows_Security.Views
{
    public sealed partial class HomePage : Page
    {
        private sealed class WeakEventTimer
        {
            private readonly DispatcherQueueTimer _timer;
            public event EventHandler<object?>? Tick;

            public WeakEventTimer(TimeSpan interval)
            {
                _timer = DispatcherQueue.GetForCurrentThread().CreateTimer();
                _timer.Interval = interval;
                _timer.Tick += (_, e) => Tick?.Invoke(this, e);
            }
            public void Start() => _timer.Start();
            public void Stop() => _timer.Stop();
        }

        private static class LogModel
        {
            private static readonly ObservableCollection<string> _lines = [];
            private static readonly DispatcherQueue _dq = DispatcherQueue.GetForCurrentThread();
            public static ObservableCollection<string> Lines => _lines;

            private const int MAX_LINES = 200;

            public static void Reload(string raw, string[]? filters)
            {
                _dq.TryEnqueue(() =>
                {
                    try
                    {
                        var q = string.IsNullOrEmpty(raw)
                            ? []
                            : raw.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries);

                        if (filters?.Length > 0)
                            q = [.. q.Where(l => filters.Any(f => l.Contains($"[{f}]")))];

                        _lines.Clear();
                        foreach (var l in q.TakeLast(MAX_LINES))
                            _lines.Add(l);
                    }
                    catch { }
                });
            }

        }

        private static class SystemInfoModel
        {
            [StructLayout(LayoutKind.Sequential)]
            private struct MEMORYSTATUSEX
            {
                public uint dwLength, dwMemoryLoad;
                public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile,
                             ullAvailPageFile, ullTotalVirtual, ullAvailVirtual,
                             ullAvailExtendedVirtual;
            }
            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

            public static (bool ok, uint load, string display) GetMemory()
            {
                var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
                if (!GlobalMemoryStatusEx(ref mem)) return (false, 0, "");
                double t = mem.ullTotalPhys, a = mem.ullAvailPhys, u = t - a;
                string[] units = ["B", "KB", "MB", "GB"];
                int idx = 0;
                while (t >= 1024 && idx < units.Length - 1) { t /= 1024; a /= 1024; u /= 1024; idx++; }
                return (true, mem.dwMemoryLoad, $"{u:F1} {units[idx]} / {t:F1} {units[idx]} ({mem.dwMemoryLoad}%)");
            }
        }

        private readonly WeakEventTimer _sysTimer = new(TimeSpan.FromSeconds(30));
        private readonly WeakEventTimer _protTimer = new(TimeSpan.FromSeconds(5));

        public string[] SelectedLogFilters = [];
        public static ObservableCollection<string> LogLines => LogModel.Lines;


        public HomePage()
        {
            InitializeComponent();

            LogRepeater.ItemsSource = LogLines;

            LogText.TextChanged += (s, e) =>
            {
                App.MainWindow?.DispatcherQueue?.TryEnqueue(() =>
                {
                    LogModel.Reload(LogText.Text, SelectedLogFilters);
                });
            };

            LoadData();
            InitTimers();
            RefreshPomes();
        }

        private void RefreshPomes_Click(object sender, RoutedEventArgs e) => RefreshPomes();
        private void CopyPomes_Click(object sender, RoutedEventArgs e)
        {
            var pkg = new DataPackage();
            pkg.SetText(PomesLine.Text);
            Clipboard.SetContent(pkg);
        }

        private void RefreshSysInfo_Click(object sender, RoutedEventArgs e) => LoadData();

        private void RefreshStatistics_Click(object sender, RoutedEventArgs e) => LoadStatistics();

        private void ClearLog_Click(object sender, RoutedEventArgs e) => LogText.ClearLog();

        private async void ExportLog_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var hwnd = WindowNative.GetWindowHandle(App.MainWindow);
                var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hwnd);
                var picker = new FileSavePicker(windowId)
                {
                    SuggestedFileName = $"XdowsSecurity_Log_{DateTime.Now:yyyyMMdd_HHmmss}.log",
                    DefaultFileExtension = ".log",
                    SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
                    SuggestedFolder = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                };

                PickFileResult file = await picker.PickSaveFileAsync();
                if (file is null) return;

                try
                {
                    File.WriteAllText(file.Path, LogText.Text);
                }
                catch (Exception ex) { LogText.AddNewLog(LogText.LogLevel.WARN, "ExportLog", ex.Message); }
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.WARN, "ExportLog", ex.Message);
            }
        }

        private void CopySysInfo_Click(object sender, RoutedEventArgs e)
        {
            var pkg = new DataPackage();
            pkg.SetText($"OSName: {OsName.Text}\nOSVersion: {OsVersion.Text}\nMemoryUsage: {MemoryUsage.Text}");
            Clipboard.SetContent(pkg);
        }

        private void LogLevelFilter_MenuClick(object sender, RoutedEventArgs e)
        {
            if (sender is not ToggleMenuFlyoutItem item) return;
            var flyout = LogLevelFilter.Flyout as MenuFlyout;
            var selected = flyout!.Items
                                  .OfType<ToggleMenuFlyoutItem>()
                                  .Where(t => t.Tag.ToString() != "All" && t.IsChecked)
                                  .Select(t => t.Tag.ToString()!)
                                  .ToArray();
            LogLevelFilter_Internal(selected);
        }

        private void RefreshPomes()
        {
            var all = Localizer.Get().GetLocalizedString("HomePage_Pomes")
                               .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
            PomesLine.Text = all.OrderBy(_ => Guid.NewGuid()).FirstOrDefault() ?? "";
        }

        private void LogLevelFilter_Internal(string[]? selected)
        {
            SelectedLogFilters = selected ?? [];
            LogModel.Reload(LogText.Text, SelectedLogFilters);
        }

        private void InitTimers()
        {
            _sysTimer.Tick += (_, _) => { UpdateMemory(); LoadProtection(); };
            _protTimer.Tick += (_, _) => UpdateData();
            _sysTimer.Start();
            _protTimer.Start();
        }

        private void LoadData()
        {
            try
            {
                OsName.Text = App.OsName;
                OsVersion.Text = App.OsVersion;
            }
            catch (Exception ex)
            {
                OsName.Text = Localizer.Get().GetLocalizedString("HomePage_GetFailed.Text");
                OsVersion.Text = Localizer.Get().GetLocalizedString("HomePage_GetFailed.Text");
                LogText.AddNewLog(LogText.LogLevel.WARN, "LoadSystemInfo", ex.Message);
            }
            UpdateMemory();
            LoadProtection();
            LoadStatistics();
            UpdateData();
        }

        private void UpdateMemory()
        {
            var (ok, _, disp) = SystemInfoModel.GetMemory();

            MemoryUsage.Text = ok ? disp : Localizer.Get().GetLocalizedString("HomePage_GetFailed.Text");
        }

        private void LoadProtection()
        {
            var st = Localizer.Get().GetLocalizedString("AllPage_Status").Split(',');
            var ok = Xdows_Security.ProtectionStatus.IsOpen();
            ProtectionStatus.Text = ok ? st[0] : st[1];
            ProtectionStatus.Foreground = ok
            ? new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(255, 78, 201, 176))
            : new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(255, 241, 82, 98));

            var lastScan = Compatibility.Windows.Storage.ApplicationData.Current.LocalSettings.Values["LastScanTime"] as string ?? "";

            LastScanTime.Text = string.IsNullOrEmpty(lastScan) ? WinUI3Localizer.Localizer.Get().GetLocalizedString("AllPage_Undefined") : lastScan;

            var threatCount = (int)(Compatibility.Windows.Storage.ApplicationData.Current.LocalSettings.Values["ThreatCount"] ?? 0);
            ThreatCount.Text = threatCount.ToString();
        }

        private void LoadStatistics()
        {
            TotalScans.Text = Statistics.ScansQuantity.ToString();
            TotalThreats.Text = Statistics.VirusQuantity.ToString();
        }

        private void UpdateData()
        {
            var ok = Xdows_Security.ProtectionStatus.IsOpen();
            HomePageText.Text = Localizer.Get().GetLocalizedString(ok ? "HomePage_TextBlock_Open"
                                                                 : "HomePage_TextBlock_Close");
            HomePageIcon.Glyph = ok ? "\uE73E" : "\uE711";
        }

    }
}
