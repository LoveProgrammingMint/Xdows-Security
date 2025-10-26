using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Windows.ApplicationModel.Resources;
using Compatibility.Windows.Storage;
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
        public HomePage()
        {
            this.InitializeComponent();
            InitializeTimers();
            InitializeData();
            LogText.TextChanged += LogText_TextChanged;
            RefreshPomes();
            UpdateData();
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
        private void RefreshPomes_Click(object sender, RoutedEventArgs e) {
            RefreshPomes();
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
                var osVersion = Environment.OSVersion;
                OSNameText.Text = "Windows " + (App.CheckWindowsVersion() ? "11" : osVersion.Version.Major.ToString());
                OSVersionText.Text = osVersion.VersionString;

                UpdateMemoryUsage();
            }
            catch (Exception ex)
            {
                OSNameText.Text = "获取失败";
                OSVersionText.Text = "获取失败";
                LogText.AddNewLog(3, "HomePage - LoadSystemInfo", $"Cannot get SystemInfo,because: {ex.Message}");
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

        private void UpdateMemoryUsage()
        {
            try
            {
                var memStatus = new MEMORYSTATUSEX
                {
                    dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX))
                };

                if (GlobalMemoryStatusEx(ref memStatus))
                {
                    string[] units = { "B", "KB", "MB", "GB", "TB" };
                    double totalMemory = memStatus.ullTotalPhys;
                    double availableMemory = memStatus.ullAvailPhys;
                    double usedMemory = totalMemory - availableMemory;

                    // 自动选择合适的单位
                    int unitIndex = 0;
                    while (totalMemory >= 1024 && unitIndex < units.Length - 1)
                    {
                        totalMemory /= 1024;
                        availableMemory /= 1024;
                        usedMemory /= 1024;
                        unitIndex++;
                    }

                    var usagePercent = memStatus.dwMemoryLoad;
                    MemoryUsageText.Text = $"{usedMemory:F1} {units[unitIndex]} / {totalMemory:F1} {units[unitIndex]} ({usagePercent:F1}%)";
                }
                else
                {
                    var error = Marshal.GetLastWin32Error();
                    MemoryUsageText.Text = "获取失败";
                    LogText.AddNewLog(3, "HomePage - UpdateMemoryUsage", $"Cannot get MemoryStatus,because: {error}");
                }
            }
            catch (Exception ex)
            {
                MemoryUsageText.Text = "获取失败";
                LogText.AddNewLog(3, "HomePage - UpdateMemoryUsage", $"Cannot get MemoryStatus,because: {ex.Message}");
            }
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



        private void UpdateScanStatistics(int totalScans, int threatsFound)
        {
            var settings = ApplicationData.Current.LocalSettings;
            var currentTotal = settings.Values["TotalScans"] as int? ?? 0;
            var currentThreats = settings.Values["TotalThreats"] as int? ?? 0;

            settings.Values["TotalScans"] = currentTotal + 1;
            settings.Values["TotalThreats"] = currentThreats + threatsFound;

            LoadStatistics();
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
            var savePicker = new FileSavePicker();
            savePicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
            savePicker.FileTypeChoices.Add("日志文件", new List<string> { ".log" });
            savePicker.SuggestedFileName = $"XdowsSecurity_Log_{DateTime.Now:yyyyMMdd_HHmmss}.log";

            var window = new Window();
            var hWnd = WinRT.Interop.WindowNative.GetWindowHandle(window);
            WinRT.Interop.InitializeWithWindow.Initialize(savePicker, hWnd);

            var file = await savePicker.PickSaveFileAsync();
            if (file != null)
            {
                try
                {
                    await Windows.Storage.FileIO.WriteTextAsync(file, LogText.Text);
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

            if (selectedTags.Count == 0)
            {
                LogTextBox.Text = LogText.Text;
                return;
            }

            var lines = LogText.Text
                               .Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
            var filteredLines = lines.Where(line =>
                selectedTags.Any(tag => line.Contains($"[{tag}]")));

            LogTextBox.Text = string.Join(Environment.NewLine, filteredLines);
        }
        private void LogText_TextChanged(object? sender, EventArgs e)
        {
            UpdateData();
        }

        private void UpdateData()
        {
            this.LogTextBox.Text = LogText.Text;
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
        }
    }
}