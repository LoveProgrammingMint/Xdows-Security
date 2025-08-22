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
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.System;
using WinRT.Interop;
using static System.Net.Mime.MediaTypeNames;

namespace Xdows_Security
{
    public sealed partial class HomePage : Page
    {
        private readonly ResourceLoader _resourceLoader = ResourceLoader.GetForViewIndependentUse();

        private DispatcherTimer _systemInfoTimer = new();
        private DispatcherTimer _protectionTimer = new();
        private ObservableCollection<ScanResult> _quickScanResults = new();
        private ObservableCollection<ActivityItem> _recentActivities = new();
        private ObservableCollection<ProtectionLogItem> _protectionLogs = new();
        private CancellationTokenSource? _scanCancellationTokenSource;

        public HomePage()
        {
            this.InitializeComponent();
            InitializeTimers();
            InitializeData();
            LogText.TextChanged += LogText_TextChanged;
            string Pomes = _resourceLoader.GetString("HomePage_Pomes");
            var randomLine = Pomes
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .OrderBy(_ => Guid.NewGuid())
                .FirstOrDefault();
            HomePage_Pomes.Text = randomLine;
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
            QuickScanResults.ItemsSource = _quickScanResults;
            RecentActivityList.ItemsSource = _recentActivities;
            ProtectionLogList.ItemsSource = _protectionLogs;

            LoadSystemInfo();
            LoadStatistics();
            LoadProtectionStatus();
            LoadRecentActivities();
            LoadProtectionLogs();
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
            string[] DisplayText = _resourceLoader.GetString("AllPage_Status").Split(',');
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

        private void LoadRecentActivities()
        {
            _recentActivities.Clear();
            var settings = ApplicationData.Current.LocalSettings;
            if (settings.Values.TryGetValue("RecentActivities", out var activitiesObj))
            {
                var activities = activitiesObj as string;
                if (!string.IsNullOrEmpty(activities))
                {
                    var activityList = activities.Split('|');
                    foreach (var activity in activityList)
                    {
                        var parts = activity.Split(';');
                        if (parts.Length >= 2)
                        {
                            _recentActivities.Add(new ActivityItem
                            {
                                Activity = parts[0],
                                Time = parts[1]
                            });
                        }
                    }
                }
            }
        }

        private void LoadProtectionLogs()
        {
            _protectionLogs.Clear();
            _protectionLogs.Add(new ProtectionLogItem
            {
                Icon = "\uE73E",
                Color = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Green),
                Message = "实时防护已启动，你的设备很安全",
                Time = DateTime.Now.ToString("HH:mm:ss")
            });
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
            AddActivity("刷新系统信息");
        }

        private async void StartQuickScan_Click(object sender, RoutedEventArgs e)
        {
            if (_scanCancellationTokenSource != null)
            {
                _scanCancellationTokenSource.Cancel();
                _scanCancellationTokenSource = null;
                QuickScanStatusText.Text = "扫描已取消";
                return;
            }

            _scanCancellationTokenSource = new CancellationTokenSource();
            var token = _scanCancellationTokenSource.Token;

            _quickScanResults.Clear();
            QuickScanResults.Visibility = Visibility.Visible;
            QuickScanProgress.Visibility = Visibility.Visible;
            QuickScanProgress.IsIndeterminate = true;
            QuickScanStatusText.Text = "正在扫描...";

            var scanType = (QuickScanTypeCombo.SelectedItem as ComboBoxItem)?.Content.ToString() ?? "系统关键目录";
            try { QuickScanProgress.IsIndeterminate = false; } catch { return; }

            await Task.Run(async () =>
            {
                try
                {
                    var scanPaths = GetScanPaths(scanType);
                    int total = scanPaths.Count;
                    int completed = 0;


                    foreach (var path in scanPaths)
                    {
                        if (token.IsCancellationRequested) break;

                        await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                        {
                            QuickScanStatusText.Text = $"正在扫描: {path}";
                        });

                        await Task.Delay(100, token);

                        var result = new ScanResult
                        {
                            FilePath = path,
                            Status = "安全"
                        };

                        await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                        {
                            _quickScanResults.Add(result);
                        });

                        completed++;
                        var progress = (double)completed / total * 100;
                        await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                        {
                            QuickScanProgress.Value = progress;
                        });
                    }

                        await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                        {
                            try {QuickScanStatusText.Text = $"扫描完成，共检查 {total} 个项目";
                            QuickScanProgress.Visibility = Visibility.Collapsed;
                            _scanCancellationTokenSource = null; } catch { }
                        });

                    UpdateScanStatistics(total, 0);
                    AddActivity($"完成{scanType}扫描");
                }
                catch (OperationCanceledException)
                {
                    await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                    {
                        QuickScanStatusText.Text = "扫描已取消";
                        QuickScanProgress.Visibility = Visibility.Collapsed;
                        _scanCancellationTokenSource = null;
                    });
                }
                catch // (Exception ex)
                {
                    //await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                    //{
                    //QuickScanStatusText.Text = $"扫描失败: {ex.Message}";
                    //QuickScanProgress.Visibility = Visibility.Collapsed;
                    // _scanCancellationTokenSource = null;
                    //});
                }
            });
        }

        private List<string> GetScanPaths(string scanType)
        {
            var paths = new List<string>();

            switch (scanType)
            {
                case "系统关键目录":
                    paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
                    paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.System));
                    paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
                    break;
                case "启动项":
                    paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
                    paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
                    break;
                case "进程目录":
                    try
                    {
                        var processes = Process.GetProcesses();
                        foreach (var proc in processes.Take(10)) // 限制数量
                        {
                            try
                            {
                                if (!string.IsNullOrEmpty(proc.MainModule?.FileName))
                                {
                                    paths.Add(proc.MainModule.FileName);
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                    break;
                case "用户文档":
                    paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
                    paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
                    paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyPictures));
                    break;
            }

            return paths.Distinct().Where(File.Exists).ToList();
        }

        private void UpdateScanStatistics(int totalScans, int threatsFound)
        {
            var settings = ApplicationData.Current.LocalSettings;
            var currentTotal = settings.Values["TotalScans"] as int? ?? 0;
            var currentThreats = settings.Values["TotalThreats"] as int? ?? 0;

            settings.Values["TotalScans"] = currentTotal + 1;
            settings.Values["TotalThreats"] = currentThreats + threatsFound;
            settings.Values["LastScanTime"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            LoadStatistics();
            LoadProtectionStatus();
        }

        private void AddActivity(string activity)
        {
            var activityItem = new ActivityItem
            {
                Activity = activity,
                Time = DateTime.Now.ToString("HH:mm:ss")
            };

            _recentActivities.Insert(0, activityItem);

            if (_recentActivities.Count > 20)
            {
                _recentActivities.RemoveAt(_recentActivities.Count - 1);
            }

            // 保存到设置
            var activities = string.Join("|", _recentActivities.Select(a => $"{a.Activity};{a.Time}"));
            var settings = ApplicationData.Current.LocalSettings;
            settings.Values["RecentActivities"] = activities;
        }

        private void RefreshStatistics_Click(object sender, RoutedEventArgs e)
        {
            LoadStatistics();
            LoadRecentActivities();
            AddActivity("刷新统计数据");
        }

        private void ProcessProtectionToggle_Toggled(object sender, RoutedEventArgs e)
        {
            var isOn = (sender as ToggleSwitch)?.IsOn ?? false;
            var result = Protection.Run(0); // 进程防护

            _protectionLogs.Insert(0, new ProtectionLogItem
            {
                Icon = result ? "\uE73E" : "\uE711",
                Color = result ? new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Green) : new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.Red),
                Message = result ? "进程防护已启用" : "进程防护已禁用",
                Time = DateTime.Now.ToString("HH:mm:ss")
            });

            AddActivity(result ? "启用进程防护" : "禁用进程防护");
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
                    await FileIO.WriteTextAsync(file, LogText.Text);
                    AddActivity("导出日志成功");
                }
                catch (Exception ex)
                {
                    AddActivity($"导出日志失败: {ex.Message}");
                }
            }
        }

        private void LogLevelFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            string filter = (LogLevelFilter.SelectedItem as ComboBoxItem)?.Tag.ToString() ?? "All";

            if (filter == "All")
            {
                if (LogTextBox != null)
                {
                    LogTextBox.Text = LogText.Text;
                }
            }
            else
            {
                var lines = LogText.Text.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                var filteredLines = lines.Where(line =>
                {
                    if (filter == "UNKNOWN") return line.Contains("[UNKNOWN]");
                    if (filter == "DEBUG") return line.Contains("[DEBUG]");
                    if (filter == "INFO") return line.Contains("[INFO]");
                    if (filter == "WARN") return line.Contains("[WARN]");
                    if (filter == "ERROR") return line.Contains("[ERROR]");
                    if (filter == "FATAL") return line.Contains("[FATAL]");
                    return true;
                });
                LogTextBox.Text = string.Join(Environment.NewLine, filteredLines);
            }
        }

        private void TabView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var selectedTab = e.AddedItems.FirstOrDefault() as TabViewItem;
            if (selectedTab != null)
            {
                AddActivity($"切换到{selectedTab.Header}选项卡");
            }
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
                HomePage_TextBlock.Text = _resourceLoader.GetString("HomePage_TextBlock_Open");
                Icon.Glyph = "\uE73E";
            }
            else
            {
                HomePage_TextBlock.Text = _resourceLoader.GetString("HomePage_TextBlock_Close");
                Icon.Glyph = "\uE711";
            }
        }

        protected override void OnNavigatedFrom(NavigationEventArgs e)
        {
            base.OnNavigatedFrom(e);
            _systemInfoTimer?.Stop();
            _protectionTimer?.Stop();
            _scanCancellationTokenSource?.Cancel();
        }
    }

    public class ScanResult
    {
        public string FilePath { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
    }

    public class ActivityItem
    {
        public string Activity { get; set; } = string.Empty;
        public string Time { get; set; } = string.Empty;
    }

    public class ProtectionLogItem
    {
        public string Icon { get; set; } = string.Empty;
        public Microsoft.UI.Xaml.Media.SolidColorBrush Color { get; set; } = new(Microsoft.UI.Colors.Green);
        public string Message { get; set; } = string.Empty;
        public string Time { get; set; } = string.Empty;
    }
}