using Compatibility.Windows.Storage;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.WindowsAPICodePack.Dialogs;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;
using Windows.ApplicationModel.Resources;
using Windows.Storage.Pickers;
using Windows.System;
using WinUI3Localizer;
using static System.Net.Mime.MediaTypeNames;

namespace Xdows_Security
{
    public sealed partial class HomePage : Page
    {
        private DispatcherTimer _systemInfoTimer = new();
        private DispatcherTimer _protectionTimer = new();
        private readonly ObservableCollection<string> _logLines = new();
        private const int MAX_LINES = 200;

        public HomePage()
        {
            this.InitializeComponent();
            LogRepeater.ItemsSource = _logLines;
            InitializeTimers();
            InitializeData();
            LogText.TextChanged += LogText_TextChanged;
            RefreshPomes();
            UpdateData();
            RefreshLogFilter();
        }

        private void InitializeTimers()
        {
            _systemInfoTimer.Interval = TimeSpan.FromSeconds(30);
            _systemInfoTimer.Tick += SystemInfoTimer_Tick;
            _systemInfoTimer.Start();

            _protectionTimer.Interval = TimeSpan.FromSeconds(5);
            _protectionTimer.Start();
        }

        private void InitializeData()
        {
            LoadSystemInfo();
            LoadStatistics();
            LoadProtectionStatus();
        }

        private void RefreshPomes_Click(object sender, RoutedEventArgs e)
        {
            RefreshPomes();
        }
        private void CopySystemInfo_Click(object sender, RoutedEventArgs e)
        {
            var package = new DataPackage();
            package.SetText($"OSName: {OSNameText.Text}\nOSVersion: {OSVersionText.Text}\nMemoryUsage: {MemoryUsageText.Text}");
            Clipboard.SetContent(package);
        }
        private void RefreshPomes()
        {
            string Pomes = Localizer.Get().GetLocalizedString("HomePage_Pomes");
            var randomLine = Pomes
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .OrderBy(_ => Guid.NewGuid())
                .FirstOrDefault();
            HomePage_Pomes.Text = randomLine;
        }

        private void LoadSystemInfo()
        {
            try
            {
                OSNameText.Text = App.OsName;
                OSVersionText.Text = App.OsVersion;
                UpdateMemoryUsage();
            }
            catch (Exception ex)
            {
                OSNameText.Text = "获取失败";
                OSVersionText.Text = "获取失败";
                LogText.AddNewLog(3, "HomePage - LoadSystemInfo", $"Cannot get SystemInfo, because: {ex.Message}");
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);
        private (bool success, uint load, ulong total, ulong avail) GetMemoryStatus()
        {
            try
            {
                var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
                return GlobalMemoryStatusEx(ref mem)
                    ? (true, mem.dwMemoryLoad, mem.ullTotalPhys, mem.ullAvailPhys)
                    : (false, 0, 0, 0);
            }
            catch (Exception ex)
            {
                LogText.AddNewLog(3, "HomePage", ex.Message);
                return (false, 0, 0, 0);
            }
        }

        private void UpdateMemoryUsage()
        {
            var (ok, load, total, avail) = GetMemoryStatus();
            if (!ok)
            {
                MemoryUsageText.Text = "获取失败";
                return;
            }
            double t = total, a = avail, u = t - a;
            string[] units = { "B", "KB", "MB", "GB" };
            int idx = 0;
            while (t >= 1024 && idx < units.Length - 1) { t /= 1024; a /= 1024; u /= 1024; idx++; }
            MemoryUsageText.Text = $"{u:F1} {units[idx]} / {t:F1} {units[idx]} ({load}%)";
        }

        private void LoadProtectionStatus()
        {
            var isProtected = Protection.IsOpen();
            string[] DisplayText = Localizer.Get().GetLocalizedString("AllPage_Status").Split(',');
            ProtectionStatusText.Text = isProtected ? DisplayText[0] : DisplayText[1];
            ProtectionStatusText.Foreground = isProtected ?
                new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Green) :
                new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Red);

            var settings = ApplicationData.Current.LocalSettings;
            if (settings.Values.TryGetValue("LastScanTime", out var lastScanTime))
            {
                LastScanText.Text = lastScanTime.ToString();
            }

            if (settings.Values.TryGetValue("ThreatCount", out var threatCount))
            {
                ThreatCountText.Text = threatCount.ToString();
            }
        }

        private void LoadStatistics()
        {
            var settings = ApplicationData.Current.LocalSettings;
            TotalScansText.Text = Statistics.ScansQuantity.ToString() ?? "0";
            TotalThreatsText.Text = Statistics.VirusQuantity.ToString() ?? "0";
        }

        private void SystemInfoTimer_Tick(object? sender, object e)
        {
            UpdateMemoryUsage();
            LoadProtectionStatus();
        }

        private void RefreshSystemInfo_Click(object sender, RoutedEventArgs e)
        {
            LoadSystemInfo();
            LoadProtectionStatus();
        }

        private void RefreshStatistics_Click(object sender, RoutedEventArgs e)
        {
            LoadStatistics();
        }

        private void ClearLog_Click(object sender, RoutedEventArgs e)
        {
            LogText.ClearLog();
        }

        private async void ExportLog_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new CommonSaveFileDialog
            {
                Title = "保存日志",
                DefaultFileName = $"XdowsSecurity_Log_{DateTime.Now:yyyyMMdd_HHmmss}.log",
                DefaultExtension = "log",
                OverwritePrompt = true,
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
            };
            dlg.Filters.Add(new CommonFileDialogFilter("日志文件", "*.log"));

            if (dlg.ShowDialog() == CommonFileDialogResult.Ok)
            {
                try
                {
                    string filePath = dlg.FileName;
                    File.WriteAllText(filePath, LogText.Text);
                }
                catch (Exception ex)
                {
                    LogText.AddNewLog(3, "HomePage - ExportLog", $"Cannot export log,because: {ex.Message}");
                }
            }
        }

        private void LogLevelFilter_MenuClick(object sender, RoutedEventArgs e)
        {
            var item = sender as ToggleMenuFlyoutItem;
            if (item == null) return;
            var flyout = LogLevelFilter.Flyout as MenuFlyout;
            if (flyout == null) return;
            var allLevelItems = flyout.Items
                                      .OfType<ToggleMenuFlyoutItem>()
                                      .Where(t => t.Tag.ToString() != "All")
                                      .ToList();
            var allItem = flyout.Items
                                .OfType<ToggleMenuFlyoutItem>()
                                .First(t => t.Tag.ToString() == "All");
            if (item.Tag.ToString() == "All")
            {
                if (item.IsChecked == true)
                {
                    bool check = item.IsChecked;
                    foreach (var lvl in allLevelItems)
                        lvl.IsChecked = check;
                }
            }
            else
            {
                bool allChecked = allLevelItems.All(t => t.IsChecked == true);
                bool noneChecked = allLevelItems.All(t => t.IsChecked == false);

                if (allChecked) allItem.IsChecked = true;
                else if (noneChecked) allItem.IsChecked = false;
                else allItem.IsChecked = false;
            }

            RefreshLogFilter();
        }

        private void RefreshLogFilter()
        {
            var flyout = LogLevelFilter.Flyout as MenuFlyout;
            if (flyout == null) return;

            var selectedTags = flyout.Items
                .OfType<ToggleMenuFlyoutItem>()
                .Where(t => t.IsChecked == true && t.Tag.ToString() != "All")
                .Select(t => t.Tag.ToString())
                .ToList();

            var lines = LogText.Text
                .Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);

            var filtered = selectedTags.Count == 0
                ? lines
                : lines.Where(l => selectedTags.Any(t => l.Contains($"[{t}]")));

            _logLines.Clear();
            foreach (var l in filtered.TakeLast(MAX_LINES))
                _logLines.Add(l);

            LogScroll.ScrollToVerticalOffset(LogScroll.ScrollableHeight);
        }

        private void LogText_TextChanged(object? sender, EventArgs e)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                var lines = LogText.Text
                                   .Split('\n')
                                   .Where(s => !string.IsNullOrWhiteSpace(s))
                                   .ToList();

                _logLines.Clear();
                foreach (var l in lines.TakeLast(MAX_LINES))
                    _logLines.Add(l);

                LogScroll.ScrollToVerticalOffset(LogScroll.ScrollableHeight);
            });
        }

        private void UpdateData()
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                if (Protection.IsOpen())
                {
                    HomePage_TextBlock.Text = Localizer.Get().GetLocalizedString("HomePage_TextBlock_Open");
                    Icon.Glyph = "\uE73E";
                }
                else
                {
                    HomePage_TextBlock.Text = Localizer.Get().GetLocalizedString("HomePage_TextBlock_Close");
                    Icon.Glyph = "\uE711";
                }
            });
        }
    }
}