using Microsoft.UI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.UI;
using WinRT.Interop;
using Xdows.ScanEngine;

namespace Xdows_Security
{
    public enum ScanMode { Quick, Full, File, Folder, More }
    public record VirusRow(string FilePath, string VirusName);

    // 扫描项目数据模型
    public class ScanItem
    {
        public string ItemName { get; set; } = string.Empty;
        public string IconGlyph { get; set; } = "&#xE721;";
        public SolidColorBrush IconColor { get; set; } = new SolidColorBrush(Colors.Gray);
        public string StatusText { get; set; } = "等待扫描";
        public int ThreatCount { get; set; } = 0;
        public Visibility ThreatCountVisibility { get; set; } = Visibility.Collapsed;
        public SolidColorBrush ThreatCountBackground { get; set; } = new SolidColorBrush(Colors.Red);
    }

    public sealed partial class SecurityPage : Page
    {
        private CancellationTokenSource? _cts;
        private readonly DispatcherQueue _dispatcherQueue;
        private ObservableCollection<VirusRow>? _currentResults;
        private List<ScanItem>? _scanItems;
        private bool _isPaused = false;
        private int _filesScanned = 0;
        private int _filesSafe = 0;
        private int _threatsFound = 0;

        public SecurityPage()
        {
            this.InitializeComponent();
            _dispatcherQueue = DispatcherQueue.GetForCurrentThread();
            PathText.Text = "扫描模式：未指定";
            InitializeScanItems();
        }

        // 初始化扫描项目
        private void InitializeScanItems()
        {
            _scanItems = new List<ScanItem>
            {
                new ScanItem { ItemName = "系统关键区域", IconGlyph = "&#xE721;" },
                new ScanItem { ItemName = "内存进程", IconGlyph = "&#xE896;" },
                new ScanItem { ItemName = "启动扫描", IconGlyph = "&#xE812;" },
                new ScanItem { ItemName = "用户文档", IconGlyph = "&#xE8A5;" }
            };
        }

        private void StartRadarAnimation()
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                if (RadarScanLine == null) return;
                RadarLineAppearStoryboard.Begin();
                RadarScanStoryboard.Begin();
            });
        }

        private void StopRadarAnimation()
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                if (RadarScanLine == null) return;
                RadarLineDisappearStoryboard.Begin();
                RadarScanStoryboard.Stop();
            });
        }

        private void PauseRadarAnimation()
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                RadarScanStoryboard.Pause();
            });
        }

        private void ResumeRadarAnimation()
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                RadarScanStoryboard.Resume();
            });
        }

        // 更新扫描区域信息
        private void UpdateScanAreaInfo(string areaName, string detailInfo)
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                CurrentScanAreaText.Text = areaName;
                ScanProgressDetailText.Text = detailInfo;
            });
        }

        // 更新扫描项目状态
        private void UpdateScanItemStatus(int itemIndex, string status, bool isActive, int threatCount = 0)
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                try
                {
                    if (_scanItems != null && itemIndex < _scanItems.Count)
                    {
                        var item = _scanItems[itemIndex];
                        item.StatusText = status;
                        item.IconColor = new SolidColorBrush(isActive ? Colors.DodgerBlue : Colors.Gray);
                        item.ThreatCount = threatCount;
                        item.ThreatCountVisibility = threatCount > 0 ? Visibility.Visible : Visibility.Collapsed;
                    }
                }
                catch { }
            });

        }

        // 更新扫描统计信息
        private void UpdateScanStats(int filesScanned, int filesSafe, int threatsFound)
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                _filesScanned = filesScanned;
                _filesSafe = filesSafe;
                _threatsFound = threatsFound;
                try
                {
                    FilesScannedText.Text = $"{filesScanned} 个文件";
                    FilesSafeText.Text = $"{filesSafe} 个安全";
                    ThreatsFoundText.Text = $"{threatsFound} 个威胁";
                }
                catch { }
            });
        }

        private void OnScanMenuClick(object sender, RoutedEventArgs e)
        {
            var settings = ApplicationData.Current.LocalSettings;
            bool UseLocalScan = settings.Values["LocalScan"] is bool && (bool)settings.Values["LocalScan"];
            bool UseCzkCloudScan = settings.Values["CzkCloudScan"] is bool && (bool)settings.Values["CzkCloudScan"];
            bool UseCloudScan = settings.Values["CloudScan"] is bool && (bool)settings.Values["CloudScan"];
            bool UseSouXiaoScan = settings.Values["SouXiaoScan"] is bool && (bool)settings.Values["SouXiaoScan"];

            if (!UseLocalScan && !UseCzkCloudScan && !UseSouXiaoScan && !UseCloudScan)
            {
                var dialog = new ContentDialog
                {
                    Title = "当前没有选择扫描引擎",
                    Content = "请转到 设置 - 扫描引擎 选择一个引擎。",
                    PrimaryButtonText = "确定",
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme,
                    PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                }.ShowAsync();
                return;
            }

            if (sender is not MenuFlyoutItem { Tag: string tag }) return;
            var mode = tag switch
            {
                "Quick" => ScanMode.Quick,
                "Full" => ScanMode.Full,
                "File" => ScanMode.File,
                "Folder" => ScanMode.Folder,
                _ => ScanMode.More
            };
            if (mode == ScanMode.More)
            {
                var dialog = new ContentDialog
                {
                    Title = "暂未实现",
                    Content = "请使用其它扫描方式进行扫描任务。",
                    PrimaryButtonText = "确定",
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme,
                    PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                }.ShowAsync();
                return;
            }


            _ = StartScanAsync(((MenuFlyoutItem)sender).Text, mode);
        }
        private int ScanId = 0;
        private async Task StartScanAsync(string displayName, ScanMode mode)
        {
            _cts?.Cancel();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            _isPaused = false;

            var settings = ApplicationData.Current.LocalSettings;
            bool showScanProgress = settings.Values["ShowScanProgress"] is bool && (bool)settings.Values["ShowScanProgress"];
            bool DeepScan = settings.Values["DeepScan"] is bool && (bool)settings.Values["DeepScan"];
            bool ExtraData = settings.Values["ExtraData"] is bool && (bool)settings.Values["ExtraData"];
            bool UseLocalScan = settings.Values["LocalScan"] is bool && (bool)settings.Values["LocalScan"];
            bool UseCzkCloudScan = settings.Values["CzkCloudScan"] is bool && (bool)settings.Values["CzkCloudScan"];
            bool UseCloudScan = settings.Values["CloudScan"] is bool && (bool)settings.Values["CloudScan"];
            bool UseSouXiaoScan = settings.Values["SouXiaoScan"] is bool && (bool)settings.Values["SouXiaoScan"];

            var SouXiaoEngine = new Xdows.ScanEngine.ScanEngine.SouXiaoEngineScan();
            if (UseSouXiaoScan)
            {
                if (!SouXiaoEngine.Initialize()){
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        var dialog = new ContentDialog
                        {
                            Title = "无法初始化 SouXiaoEngine",
                            Content = "请转到 设置 - 扫描引擎 取消这个引擎的选中。",
                            PrimaryButtonText = "确定",
                            XamlRoot = this.XamlRoot,
                            RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme,
                            PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                        }.ShowAsync();
                    });
                    return;
                }
            }

            string Log = "Use";
            if (UseLocalScan)
            {
                Log += " LocalScan";
                if (DeepScan) { Log += "-DeepScan"; }
            }
            if (UseCzkCloudScan)
            {
                Log += " CzkCloudScan";
            }
            if (UseCloudScan)
            {
                Log += " CloudScan";
            }
            if (UseSouXiaoScan)
            {
                Log += " SouXiaoScan";
            }
            LogText.AddNewLog(1, "Security - StartScan", Log);

            string? userPath = null;
            if (mode is ScanMode.File or ScanMode.Folder)
            {
                userPath = await PickPathAsync(mode);
                if (string.IsNullOrEmpty(userPath))
                {
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        ScanProgress.Visibility = Visibility.Collapsed;
                        StatusText.Text = "取消选择";
                        StopRadarAnimation();
                    });
                    return;
                }
            }

            ScanButton.IsEnabled = false;

            // 重置统计信息
            _filesScanned = 0;
            _filesSafe = 0;
            _threatsFound = 0;
            UpdateScanStats(0, 0, 0);

            // 重置扫描项目状态
            for (int i = 0; i < _scanItems!.Count; i++)
            {
                UpdateScanItemStatus(i, "等待扫描", false, 0);
            }

            _currentResults = new ObservableCollection<VirusRow>();
            _dispatcherQueue.TryEnqueue(() =>
            {
                ScanProgress.IsIndeterminate = !showScanProgress;
                VirusList.ItemsSource = _currentResults;
                VirusList.Visibility = Visibility.Collapsed;
                BackToVirusListButton.Visibility = Visibility.Collapsed;
                ScanProgress.Value = 0;
                ScanProgress.Visibility = Visibility.Visible;
                ProgressPercentText.Text = showScanProgress? "0%":String.Empty;
                PathText.Text = $"扫描模式：{displayName}";
                PauseScanButton.Visibility = Visibility.Visible;
                PauseScanButton.IsEnabled = false;
                ResumeScanButton.Visibility = Visibility.Collapsed;
                StatusText.Text = "正在处理文件...";
                StartRadarAnimation();
            });
            ScanId += 1;
            await Task.Run(async () =>
            {
                try
                {
                    var files = EnumerateFiles(mode, userPath);
                    int ThisId = ScanId;
                    int total = files.Count();
                    int finished = 0;
                    int currentItemIndex = 0;
                    switch (mode)
                    {
                        case ScanMode.Quick:
                            UpdateScanAreaInfo("快速扫描系统关键区域", "正在检测系统关键文件和目录");
                            currentItemIndex = 0;
                            break;
                        case ScanMode.Full:
                            UpdateScanAreaInfo("全面扫描所有磁盘", "正在检测所有磁盘的文件");
                            currentItemIndex = 1;
                            break;
                        case ScanMode.File:
                            UpdateScanAreaInfo("单独扫描指定文件", $"正在检测：{userPath}");
                            currentItemIndex = 2;
                            break;
                        case ScanMode.Folder:
                            UpdateScanAreaInfo("单独扫描指定目录", $"正在检测：{userPath}");
                            currentItemIndex = 3;
                            break;
                    }

                    // 激活当前扫描项目
                    UpdateScanItemStatus(currentItemIndex, "正在扫描", true);

                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        PauseScanButton.IsEnabled = true;
                    });

                    foreach (var file in files)
                    {
                        while (_isPaused && !token.IsCancellationRequested)
                        {
                            await Task.Delay(100, token);
                        }

                        if (token.IsCancellationRequested) break;

                        _dispatcherQueue.TryEnqueue(() =>
                        {
                            LogText.AddNewLog(1, "Security - ScanFile", file);
                            try
                            {
                                StatusText.Text = $"正在扫描：{file}";
                            }
                            catch
                            {
                            }
                        });

                        try
                        {
                            string Result = string.Empty;

                            if (UseSouXiaoScan)
                            {
                                if (SouXiaoEngine != null)
                                {
                                    var SouXiaoEngineResult = SouXiaoEngine.ScanFile(file);
                                    Result = SouXiaoEngineResult.IsVirus ? SouXiaoEngineResult.Result : string.Empty;
                                }
                            }
                            if (string.IsNullOrEmpty(Result))
                            {
                                if (UseLocalScan)
                                {
                                    string localResult = await Xdows.ScanEngine.ScanEngine.LocalScanAsync(file, DeepScan, ExtraData);

                                    if (!string.IsNullOrEmpty(localResult))
                                    {
                                        Result = DeepScan ? $"{localResult} with DeepScan" : localResult;
                                    }
                                }
                            }

                            if (string.IsNullOrEmpty(Result))
                            {
                                if (UseCloudScan)
                                {
                                    var cloudResult = await Xdows.ScanEngine.ScanEngine.CloudScanAsync(file);
                                    System.Diagnostics.Debug.WriteLine(cloudResult.result);
                                    if (cloudResult.result == "virus_file")
                                    {
                                        Result = "MEMZUAC.Cloud.VirusFile" ?? string.Empty;
                                    }
                                }
                            }
                            if (string.IsNullOrEmpty(Result))
                            {
                                if (UseCzkCloudScan)
                                {
                                    var czkCloudResult = await Xdows.ScanEngine.ScanEngine.CzkCloudScanAsync(file, App.GetCzkCloudApiKey());
                                    if (czkCloudResult.result != "safe")
                                    {
                                        Result = czkCloudResult.result??string.Empty;
                                    }
                                }
                            }
                            Statistics.ScansQuantity += 1;
                            if (!string.IsNullOrEmpty(Result))
                            {
                                LogText.AddNewLog(1, "Security - Find", Result);
                                Statistics.VirusQuantity += 1;
                                try
                                {
                                    _dispatcherQueue.TryEnqueue(() =>
                                    {
                                        _currentResults!.Add(new VirusRow(file, Result));
                                        BackToVirusListButton.Visibility = Visibility.Visible;
                                    });
                                    _threatsFound++;
                                    UpdateScanItemStatus(currentItemIndex, "发现威胁", true, _threatsFound);
                                }
                                catch { }
                            }
                            else
                            {
                                LogText.AddNewLog(1, "Security - Find", "Is Safe");
                                _filesSafe++;
                            }

                        }
                        catch
                        {
                            // 忽略无法访问的文件
                        }

                        finished++;
                        _filesScanned = finished;

                        if (showScanProgress)
                        {
                            var percent = total == 0 ? 100 : (double)finished / total * 100;
                            _dispatcherQueue.TryEnqueue(() =>
                            {
                                ScanProgress.Value = percent;
                                ProgressPercentText.Text = $"{percent:F0}%";
                            });
                        }
                        try
                        {
                            UpdateScanStats(_filesScanned, _filesSafe, _threatsFound);
                        }
                        catch { }
                        // 检测是否已经退出这个页面
                        if (MainWindow.NowPage != "Security" | ThisId != ScanId)
                        {
                            break;
                        }
                        await Task.Delay(1, token);
                    }

                    // 完成当前扫描项目
                    UpdateScanItemStatus(currentItemIndex, "扫描完成", false, _threatsFound);

                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        var settings = ApplicationData.Current.LocalSettings;
                        settings.Values["LastScanTime"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

                        StatusText.Text = $"扫描完成，发现 {_currentResults.Count} 个威胁";
                        ScanProgress.Visibility = Visibility.Collapsed;
                        PauseScanButton.Visibility = Visibility.Collapsed;
                        ResumeScanButton.Visibility = Visibility.Collapsed;

                        StopRadarAnimation();
                    });
                }
                catch (OperationCanceledException)
                {
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        StatusText.Text = "扫描已取消";
                        ScanProgress.Visibility = Visibility.Collapsed;
                        PauseScanButton.Visibility = Visibility.Collapsed;
                        ResumeScanButton.Visibility = Visibility.Collapsed;

                        StopRadarAnimation();
                    });
                }
                catch (Exception ex)
                {
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        LogText.AddNewLog(4, "Security - Failed", ex.Message);
                        StatusText.Text = $"扫描失败：{ex.Message}";
                        ScanProgress.Visibility = Visibility.Collapsed;
                        PauseScanButton.Visibility = Visibility.Collapsed;
                        ResumeScanButton.Visibility = Visibility.Collapsed;

                        StopRadarAnimation();
                    });
                }
            });
            ScanButton.IsEnabled = true;
        }

        // 返回病毒列表按钮事件
        private void OnBackToVirusListClick(object sender, RoutedEventArgs e)
        {
            bool show = VirusList.Visibility != Visibility.Visible;
            VirusList.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
            BackToVirusListButtonText.Text = show ? "隐藏列表" : "显示列表";
            BackToVirusListButtonIcon.Glyph = show ? "\uED1A" : "\uE890";
        }

        // 暂停扫描按钮事件
        private void OnPauseScanClick(object sender, RoutedEventArgs e)
        {
            _isPaused = true;
            ScanButton.IsEnabled = true;
            PauseScanButton.Visibility = Visibility.Collapsed;
            ResumeScanButton.Visibility = Visibility.Visible;
            UpdateScanAreaInfo("扫描已暂停", "请点击继续扫描按钮恢复扫描");

            PauseRadarAnimation();
        }

        // 继续扫描按钮事件
        private void OnResumeScanClick(object sender, RoutedEventArgs e)
        {
            _isPaused = false;
            ScanButton.IsEnabled = false;
            PauseScanButton.Visibility = Visibility.Visible;
            ResumeScanButton.Visibility = Visibility.Collapsed;
            UpdateScanAreaInfo("正在继续扫描", "扫描进程已恢复");

            ResumeRadarAnimation();
        }

        private async void VirusList_DoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
        {
            if ((sender as ListView)?.SelectedItem is VirusRow row)
            {
                await ShowDetailsDialog(row);
            }
        }

        private async void OnDetailClick(object sender, RoutedEventArgs e)
        {
            if ((sender as MenuFlyoutItem)?.Tag is VirusRow row)
                await ShowDetailsDialog(row);
        }

        private async void OnDeleteClick(object sender, RoutedEventArgs e)
        {
            if ((sender as MenuFlyoutItem)?.Tag is not VirusRow row ||
                _currentResults is null) return;

            var dialog = new ContentDialog
            {
                Title = "确认要删除此文件吗",
                Content = $"确定要删除此文件\n{row.FilePath}\n这将永久删除文件，无法恢复",
                PrimaryButtonText = "删除",
                CloseButtonText = "取消",
                XamlRoot = this.XamlRoot,
                RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme,
                PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
            };
            if (await dialog.ShowAsync() == ContentDialogResult.Primary)
            {
                try
                {
                    File.Delete(row.FilePath);
                    var itemToRemove = _currentResults.FirstOrDefault(r => r.FilePath == row.FilePath && r.VirusName == row.VirusName);
                    if (itemToRemove != null)
                    {
                        _currentResults.Remove(itemToRemove);
                    }
                    _threatsFound--;
                    UpdateScanStats(_filesScanned, _filesSafe, _threatsFound);
                    StatusText.Text = $"扫描完成，发现 {_currentResults.Count} 个威胁";
                }
                catch (Exception ex)
                {
                    await new ContentDialog
                    {
                        Title = "删除失败",
                        Content = ex.Message,
                        CloseButtonText = "确定",
                        RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme,
                        XamlRoot = this.XamlRoot,
                        CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                    }.ShowAsync();
                }
            }
        }
        private async Task ShowDetailsDialog(VirusRow row)
        {
            try
            {
                var fileInfo = new FileInfo(row.FilePath);
                var dialog = new ContentDialog
                {
                    Title = "详细信息",
                    Content = new ScrollViewer
                    {
                        Content = new StackPanel
                        {
                            Children =
                            {
                                new TextBlock { Text = $"文件路径：", Margin = new Thickness(0, 8, 0, 0) },
                                new RichTextBlock
                                {
                                    IsTextSelectionEnabled = true,
                                    TextWrapping = TextWrapping.Wrap,
                                    FontSize = 14,
                                    FontFamily = new FontFamily("Segoe UI"),
                                    Blocks =
                                    {
                                        new Paragraph
                                        {
                                            Inlines =
                                            {
                                                new Run { Text = row.FilePath},
                                            }
                                        }
                                    }
                                },
                                new TextBlock { Text = $"威胁名称：{row.VirusName}", Margin = new Thickness(0, 8, 0, 0) },
                                new TextBlock { Text = $"文件大小：{fileInfo.Length / 1024:F2} KB", Margin = new Thickness(0, 8, 0, 0) },
                                new TextBlock { Text = $"创建时间：{fileInfo.CreationTime}", Margin = new Thickness(0, 8, 0, 0) },
                                new TextBlock { Text = $"修改时间：{fileInfo.LastWriteTime}", Margin = new Thickness(0, 8, 0, 0) }
                            }
                        },
                        MaxHeight = 400
                    },
                    CloseButtonText = "确定",
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme,
                    CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                };
                await dialog.ShowAsync();
            }
            catch (Exception ex)
            {
                await new ContentDialog
                {
                    Title = "获取失败",
                    Content = ex.Message,
                    CloseButtonText = "确定",
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme,
                    CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                }.ShowAsync();
            }
        }

        #region 文件选择和枚举
        private async Task<string?> PickPathAsync(ScanMode mode)
        {
            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(App.MainWindow);

            if (mode == ScanMode.File)
            {
                var filePicker = new FileOpenPicker();
                filePicker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
                filePicker.FileTypeFilter.Add("*");
                WinRT.Interop.InitializeWithWindow.Initialize(filePicker, hwnd);

                var file = await filePicker.PickSingleFileAsync();
                return file?.Path;
            }
            else
            {
                var folderPicker = new FolderPicker();
                folderPicker.SuggestedStartLocation = PickerLocationId.ComputerFolder;
                folderPicker.FileTypeFilter.Add("*");
                WinRT.Interop.InitializeWithWindow.Initialize(folderPicker, hwnd);

                var folder = await folderPicker.PickSingleFolderAsync();
                return folder?.Path;
            }
        }

        private IReadOnlyList<string> EnumerateFiles(ScanMode mode, string? userPath) =>
            mode switch
            {
                ScanMode.Quick => EnumerateQuickScanFiles().ToList(),
                ScanMode.Full => EnumerateFullScanFiles().ToList(),
                ScanMode.File => (userPath != null && File.Exists(userPath))
                                  ? new[] { userPath }
                                  : Array.Empty<string>(),
                ScanMode.Folder => (userPath != null && Directory.Exists(userPath))
                                  ? SafeEnumerateFolder(userPath).ToList()
                                  : Array.Empty<string>(),
                _ => Array.Empty<string>()
            };

        private static IEnumerable<string> SafeEnumerateFolder(string folder)
        {
            var stack = new Stack<string>();
            stack.Push(folder);

            while (stack.Count > 0)
            {
                var dir = stack.Pop();

                IEnumerable<string> entries;
                try { entries = Directory.EnumerateFileSystemEntries(dir); }
                catch { continue; }

                foreach (var entry in entries)
                {
                    System.IO.FileAttributes attr;
                    try { attr = File.GetAttributes(entry); }
                    catch { continue; }

                    if ((attr & System.IO.FileAttributes.Directory) != 0)
                        stack.Push(entry);
                    else
                        yield return entry;
                }
            }
        }

        private IEnumerable<string> EnumerateQuickScanFiles()
        {
            var criticalPaths = new[]
            {
                 Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                 Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                 Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                 Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                 Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                 Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                 Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"),
                 Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64")
            };

            var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".sys" };

            return criticalPaths
                   .Where(Directory.Exists)
                   .SelectMany(dir =>
                   {
                       try
                       {
                           return Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly)
                                           .Where(f => extensions.Contains(Path.GetExtension(f)));
                       }
                       catch
                       {
                           return Enumerable.Empty<string>();
                       }
                   })
                   .Distinct(StringComparer.OrdinalIgnoreCase);
        }

        private IEnumerable<string> EnumerateFullScanFiles()
        {
            var scanned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady || drive.DriveType is DriveType.CDRom or DriveType.Network)
                    continue;

                foreach (var file in SafeEnumerateFiles(drive.RootDirectory.FullName, scanned))
                    yield return file;
            }
        }

        private IEnumerable<string> SafeEnumerateFiles(string root, HashSet<string> scanned)
        {
            var stack = new Stack<string>();
            stack.Push(root);

            while (stack.Count > 0)
            {
                var currentDir = stack.Pop();

                if (!scanned.Add(currentDir))
                    continue;

                IEnumerable<string>? entries = null;
                try
                {
                    entries = Directory.EnumerateFileSystemEntries(currentDir);
                }
                catch
                {
                    continue;
                }

                foreach (var entry in entries)
                {
                    if (Directory.Exists(entry))
                    {
                        stack.Push(entry);
                    }
                    else if (File.Exists(entry) && scanned.Add(entry))
                    {
                        yield return entry;
                    }
                }
            }
        }
        #endregion
    }
}
