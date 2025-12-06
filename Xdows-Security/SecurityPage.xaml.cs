using CommunityToolkit.WinUI;
using Compatibility.Windows.Storage;
using Microsoft.UI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.WindowsAPICodePack.Dialogs;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;
using WinUI3Localizer;
using Xdows.Protection;
      
namespace Xdows_Security
{
    public enum ScanMode { Quick, Full, File, Folder, More }
    public record VirusRow(string FilePath, string VirusName);

    public class ScanItem
    {
        public string ItemName { get; set; } = string.Empty;
        public string IconGlyph { get; set; } = "&#xE721;";
        public SolidColorBrush IconColor { get; set; } = new SolidColorBrush(Colors.Gray);
        public string StatusText { get; set; } = Localizer.Get().GetLocalizedString("SecurityPage_Status_Waiting");
        public int ThreatCount { get; set; } = 0;
        public Visibility ThreatCountVisibility { get; set; } = Visibility.Collapsed;
        public SolidColorBrush ThreatCountBackground { get; set; } = new SolidColorBrush(Colors.Red);
    }

    public class MoreScanItem : INotifyPropertyChanged
    {
        private string _path = string.Empty;
        private bool _isFolder;

        public string Path
        {
            get => _path;
            set { _path = value; OnPropertyChanged(); }
        }

        public bool IsFolder
        {
            get => _isFolder;
            set { _isFolder = value; OnPropertyChanged(); OnPropertyChanged(nameof(IconGlyph)); }
        }

        public string IconGlyph => _isFolder ? "\uE8B7" : "\uE8A5";

        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string name = null!)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
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
        private int ScanId = 0;
        private ContentDialog? _moreScanDialog;

        public SecurityPage()
        {
            this.InitializeComponent();
            _dispatcherQueue = DispatcherQueue.GetForCurrentThread();
            PathText.Text = Loc("SecurityPage_PathText_Default");
            ScanStatusHeader.Text = Loc("SecurityPage_ScanStatusHeader");
            ProgressHeader.Text = Loc("SecurityPage_ProgressHeader");
            ScanSpeedText.Text = string.Format(Loc("SecurityPage_ScanSpeed_Format"), 0.0);
            FilesScannedText.Text = string.Format(Loc("SecurityPage_FilesScanned_Format"), 0);
            FilesSafeText.Text = string.Format(Loc("SecurityPage_FilesSafe_Format"), 0);
            ThreatsFoundText.Text = string.Format(Loc("SecurityPage_ThreatsFound_Format"), 0);
            InitializeScanItems();
        }

        private void InitializeScanItems()
        {
            _scanItems = new List<ScanItem>
            {
                new ScanItem { ItemName = Loc("SecurityPage_ScanItem_System"), IconGlyph = "&#xE721;", StatusText = Loc("SecurityPage_Status_Waiting") },
                new ScanItem { ItemName = Loc("SecurityPage_ScanItem_Memory"), IconGlyph = "&#xE896;", StatusText = Loc("SecurityPage_Status_Waiting") },
                new ScanItem { ItemName = Loc("SecurityPage_ScanItem_Startup"), IconGlyph = "&#xE812;", StatusText = Loc("SecurityPage_Status_Waiting") },
                new ScanItem { ItemName = Loc("SecurityPage_ScanItem_UserDocs"), IconGlyph = "&#xE8A5;", StatusText = Loc("SecurityPage_Status_Waiting") }
            };
        }
        private string Loc(string key)
        {
            try
            {
                var s = Localizer.Get().GetLocalizedString(key);
                if (!string.IsNullOrEmpty(s)) return s;

                string[] suffixes = new[] { ".Text", ".Content", ".Header", ".Title", ".Description" };
                foreach (var suf in suffixes)
                {
                    s = Localizer.Get().GetLocalizedString(key + suf);
                    if (!string.IsNullOrEmpty(s)) return s;
                }

                return string.Empty;
            }
            catch
            {
                return string.Empty;
            }
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

        private void UpdateScanAreaInfo(string areaName, string detailInfo)
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                CurrentScanAreaText.Text = areaName;
                ScanProgressDetailText.Text = detailInfo;
            });
        }

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

        private void UpdateScanStats(int filesScanned, int filesSafe, int threatsFound)
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                _filesScanned = filesScanned;
                _filesSafe = filesSafe;
                _threatsFound = threatsFound;
                try
                {
                    FilesScannedText.Text = string.Format(Loc("SecurityPage_FilesScanned_Format"), filesScanned);
                    FilesSafeText.Text = string.Format(Loc("SecurityPage_FilesSafe_Format"), filesSafe);
                    ThreatsFoundText.Text = string.Format(Loc("SecurityPage_ThreatsFound_Format"), threatsFound);
                }
                catch { }
            });
        }

        private async void OnScanMenuClick(object sender, RoutedEventArgs e)
        {
            var settings = ApplicationData.Current.LocalSettings;
            bool UseLocalScan = (settings.Values["LocalScan"] as bool?).GetValueOrDefault();
            bool UseCzkCloudScan = (settings.Values["CzkCloudScan"] as bool?).GetValueOrDefault();
            bool UseCloudScan = (settings.Values["CloudScan"] as bool?).GetValueOrDefault();
            bool UseSouXiaoScan = (settings.Values["SouXiaoScan"] as bool?).GetValueOrDefault();
            bool UseJiSuSafeAX = (settings.Values["JiSuSafeAX"] as bool?).GetValueOrDefault();
            if (!UseLocalScan && !UseCzkCloudScan && !UseSouXiaoScan && !UseCloudScan && !UseJiSuSafeAX)
            {
                var dialog = new ContentDialog
                {
                    Title = Loc("SecurityPage_NoEngine_Title"),
                    Content = Loc("SecurityPage_NoEngine_Content"),
                    PrimaryButtonText = Loc("Button_Confirm"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                };
                _ = dialog.ShowAsync();
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
                var paths = await ShowMoreScanDialogAsync();
                if (paths.Count > 0)
                {
                    await StartScanAsync(Loc("SecurityPage_ScanMenu_More"), ScanMode.More, paths);
                }
                return;
            }

            await StartScanAsync(((MenuFlyoutItem)sender).Text, mode);
        }

        private async Task<IReadOnlyList<string>> ShowMoreScanDialogAsync()
        {
            var items = new ObservableCollection<MoreScanItem>();
            var listView = new ListView
            {
                ItemTemplate = Resources["MoreScanListTemplate"] as DataTemplate,
                ItemsSource = items,
                Height = 240
            };

            var browseFolderButton = new Button { Content = Loc("SecurityPage_More_BrowseFolder") };
            browseFolderButton.Click += OnMoreScanBrowseFolderClick;
            var browseFileButton = new Button { Content = Loc("SecurityPage_More_BrowseFile") };
            browseFileButton.Click += OnMoreScanBrowseFileClick;
            var removeFileButton = new Button { Content = Loc("SecurityPage_More_RemoveItem") };
            removeFileButton.Click += OnMoreScanRemovePathClick;
            var clearButton = new Button { Content = Loc("SecurityPage_More_ClearAll"), IsEnabled = false };
            clearButton.Click += OnMoreScanClearClick;

            items.CollectionChanged += (s, e) => {
                clearButton.IsEnabled = items.Count > 0;
            };

            var contentGrid = new Grid { RowSpacing = 12 };
            contentGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            contentGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            Grid.SetRow(listView, 0);

            var buttonPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 8,
                Children = { browseFolderButton, browseFileButton,removeFileButton, clearButton }
            };
            Grid.SetRow(buttonPanel, 1);

            contentGrid.Children.Add(listView);
            contentGrid.Children.Add(buttonPanel);

            _moreScanDialog = new ContentDialog
            {
                Title = Loc("SecurityPage_MoreScan_Title"),
                Content = contentGrid,
                PrimaryButtonText = Loc("SecurityPage_StartScanButton"),
                CloseButtonText = Loc("Button_Cancel"),
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = this.XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                Width = 600,
                Height = 450
            };

            var result = await _moreScanDialog.ShowAsync();
            _moreScanDialog = null;

            if (result == ContentDialogResult.Primary)
            {
                return items.Select(i => i.Path).ToList();
            }
            return new List<string>();
        }
        private void OnMoreScanRemovePathClick(object sender, RoutedEventArgs e)
        {
            var listView = FindChild<ListView>(_moreScanDialog?.Content as DependencyObject);
            if (listView?.SelectedItem is MoreScanItem item)
            {
                if (listView.ItemsSource is ObservableCollection<MoreScanItem> items)
                {
                    items.Remove(item);
                    }
                }
            else
            {
            }
        }
        private async void OnMoreScanBrowseFolderClick(object sender, RoutedEventArgs e)
        {
            using var dlg = new CommonOpenFileDialog
            {
                Title = Loc("SecurityPage_SelectFolder_Title"),
                IsFolderPicker = true,
                EnsurePathExists = true
            };

            if (dlg.ShowDialog() == CommonFileDialogResult.Ok)
            {
                await AddPathToMoreScanList(dlg.FileName, true);
            }
        }

        private async void OnMoreScanBrowseFileClick(object sender, RoutedEventArgs e)
        {
            using var dlg = new CommonOpenFileDialog
            {
                Title = Loc("SecurityPage_SelectFile_Title"),
                IsFolderPicker = false,
                EnsurePathExists = true
            };

            if (dlg.ShowDialog() == CommonFileDialogResult.Ok)
            {
                await AddPathToMoreScanList(dlg.FileName, false);
            }
        }

        private async Task AddPathToMoreScanList(string path, bool isFolder)
        {
            var listView = FindChild<ListView>(_moreScanDialog?.Content as DependencyObject);
            if (listView?.ItemsSource is not ObservableCollection<MoreScanItem> items) return;

            var existingPaths = new HashSet<string>(items.Select(i => i.Path), StringComparer.OrdinalIgnoreCase);

            if (existingPaths.Contains(path))
            {
                var dup = new ContentDialog
                {
                    Title = Loc("SecurityPage_DuplicatePath_Title"),
                    Content = string.Format(Loc("SecurityPage_DuplicatePath_Content"), path),
                    CloseButtonText = Loc("Button_Confirm"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
                };
                _ = dup.ShowAsync();
                return;
            }

            items.Add(new MoreScanItem { Path = path, IsFolder = isFolder });
        }

        private void OnMoreScanClearClick(object sender, RoutedEventArgs e)
        {
            var listView = FindChild<ListView>(_moreScanDialog?.Content as DependencyObject);
            if (listView?.ItemsSource is ObservableCollection<MoreScanItem> items)
            {
                items.Clear();
            }
        }

        private T? FindChild<T>(DependencyObject? parent) where T : DependencyObject
        {
            if (parent == null) return null;

            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                var child = VisualTreeHelper.GetChild(parent, i);
                if (child is T typedChild)
                    return typedChild;

                var result = FindChild<T>(child);
                if (result != null)
                    return result;
            }
            return null;
        }

        private async Task StartScanAsync(string displayName, ScanMode mode, IReadOnlyList<string>? customPaths = null)
        {
            _cts?.Cancel();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            _isPaused = false;

            var settings = ApplicationData.Current.LocalSettings;
            bool showScanProgress = settings.Values["ShowScanProgress"] as bool? ?? false;
            bool DeepScan = settings.Values["DeepScan"] as bool? ?? false;
            bool ExtraData = settings.Values["ExtraData"] as bool? ?? false;
            bool UseLocalScan = settings.Values["LocalScan"] as bool? ?? false;
            bool UseCzkCloudScan = settings.Values["CzkCloudScan"] as bool? ?? false;
            bool UseCloudScan = settings.Values["CloudScan"] as bool? ?? false;
            bool UseSouXiaoScan = settings.Values["SouXiaoScan"] as bool? ?? false;
            bool UseJiSuSafeAX = settings.Values["JiSuSafeAX"] as bool? ?? false;

            var SouXiaoEngine = new Xdows.ScanEngine.ScanEngine.SouXiaoEngineScan();
            if (UseSouXiaoScan)
            {
                    if (!SouXiaoEngine.Initialize())
                {
                    _dispatcherQueue.TryEnqueue(async () =>
                    {
                        var dialog = new ContentDialog
                        {
                            Title = Loc("SecurityPage_SouXiao_InitFailed_Title"),
                            Content = Loc("SecurityPage_SouXiao_InitFailed_Content"),
                            PrimaryButtonText = Loc("Button_Confirm"),
                            XamlRoot = this.XamlRoot,
                            RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                            PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                        };
                        await dialog.ShowAsync();
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
            if (UseJiSuSafeAX)
            {
                Log += " JiSuSafeAX";
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
                        StatusText.Text = Loc("SecurityPage_Status_Cancelled");
                        StopRadarAnimation();
                    });
                    return;
                }
            }

            ScanButton.IsEnabled = false;

            _filesScanned = 0;
            _filesSafe = 0;
            _threatsFound = 0;
            UpdateScanStats(0, 0, 0);

            for (int i = 0; i < _scanItems!.Count; i++)
            {
                UpdateScanItemStatus(i, Loc("SecurityPage_Status_Waiting"), false, 0);
            }

            _currentResults = new ObservableCollection<VirusRow>();
            _dispatcherQueue.TryEnqueue(() =>
            {
                ScanProgress.IsIndeterminate = !showScanProgress;
                VirusList.ItemsSource = _currentResults;
                ScanProgress.Value = 0;
                ScanProgress.Visibility = Visibility.Visible;
                ProgressPercentText.Text = showScanProgress ? "0%" : String.Empty;
                PathText.Text = string.Format(Loc("SecurityPage_PathText_Format"), displayName);
                BackToVirusListButton.Visibility = Visibility.Collapsed;
                PauseScanButton.Visibility = Visibility.Visible;
                PauseScanButton.IsEnabled = false;
                ResumeScanButton.Visibility = Visibility.Collapsed;
                StatusText.Text = Loc("SecurityPage_Status_Processing");
                OnBackList(false);
                StartRadarAnimation();
            });
            ScanId += 1;
            await Task.Run(async () =>
            {
                try
                {
                    var files = EnumerateFiles(mode, userPath, customPaths);
                    int ThisId = ScanId;
                    int total = files.Count();
                    var startTime = DateTime.Now;
                    int finished = 0;
                    int currentItemIndex = 0;
                    switch (mode)
                    {
                        case ScanMode.Quick:
                            UpdateScanAreaInfo(Loc("SecurityPage_Area_Quick_Title"), Loc("SecurityPage_Area_Quick_Detail"));
                            currentItemIndex = 0;
                            break;
                        case ScanMode.Full:
                            UpdateScanAreaInfo(Loc("SecurityPage_Area_Full_Title"), Loc("SecurityPage_Area_Full_Detail"));
                            currentItemIndex = 1;
                            break;
                        case ScanMode.File:
                            UpdateScanAreaInfo(Loc("SecurityPage_Area_File_Title"), string.Format(Loc("SecurityPage_Area_File_Detail"), userPath));
                            currentItemIndex = 2;
                            break;
                        case ScanMode.Folder:
                            UpdateScanAreaInfo(Loc("SecurityPage_Area_Folder_Title"), string.Format(Loc("SecurityPage_Area_Folder_Detail"), userPath));
                            currentItemIndex = 3;
                            break;
                        case ScanMode.More:
                            UpdateScanAreaInfo(Loc("SecurityPage_Area_More_Title"), string.Format(Loc("SecurityPage_Area_More_Detail"), customPaths?.Count ?? 0));
                            currentItemIndex = 0;
                            break;
                    }

                    UpdateScanItemStatus(currentItemIndex, Loc("SecurityPage_Status_Scanning"), true);

                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        PauseScanButton.IsEnabled = true;
                    });
                    var tStatusText = Loc("SecurityPage_Status_Scanning");
                    var pausedTime = TimeSpan.Zero; // 记录总的暂停时间
                    var lastPauseTime = DateTime.MinValue; // 记录上次暂停开始的时间
                    foreach (var file in files)
                    {
                        while (_isPaused && !token.IsCancellationRequested)
                        {
                            // 如果刚开始暂停，记录暂停开始时间
                            if (lastPauseTime == DateTime.MinValue)
                            {
                                lastPauseTime = DateTime.Now;
                            }
                            await Task.Delay(100, token);
                        }

                        // 如果刚刚恢复扫描，计算暂停时间并累加
                        if (lastPauseTime != DateTime.MinValue)
                        {
                            pausedTime += DateTime.Now - lastPauseTime;
                            lastPauseTime = DateTime.MinValue; // 重置暂停时间
                        }

                        if (token.IsCancellationRequested) break;

                            _dispatcherQueue.TryEnqueue(() =>
                            {
                                LogText.AddNewLog(1, "Security - ScanFile", file);
                                try
                                {
                                    StatusText.Text = string.Format(tStatusText, file);
                                }
                                catch
                                {
                                }
                            });

                        try
                        {
                            string Result = string.Empty;

                            // 检查文件是否在信任区中
                            if (TrustManager.IsPathTrusted(file))
                            {
                                LogText.AddNewLog(1, "Security - Find", "Is Trusted (Path)");
                                _filesSafe++;
                                continue;
                            }
                            
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
                                if (UseJiSuSafeAX)
                                {
                                    var jiSuSafeAXResult = await Xdows.ScanEngine.ScanEngine.AXScanFileAsync(file);
                                    if (!string.IsNullOrEmpty(jiSuSafeAXResult.result) && jiSuSafeAXResult.statusCode == 200)
                                    {
                                        Result = $"JiSuSafeAX.{jiSuSafeAXResult.result}";
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
                                        Result = "MEMZUAC.Cloud.VirusFile";
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
                                        Result = czkCloudResult.result ?? string.Empty;
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
                                        _currentResults?.Add(new VirusRow(file, Result));
                                        BackToVirusListButton.Visibility = Visibility.Visible;
                                    });
                                    _threatsFound++;
                                    UpdateScanItemStatus(currentItemIndex, Loc("SecurityPage_Status_FoundThreat"), true, _threatsFound);
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
                        }

                        finished++;
                        _filesScanned = finished;
                        var elapsedTime = DateTime.Now - startTime - pausedTime; // 减去暂停时间
                        var scanSpeed = finished / elapsedTime.TotalSeconds;
                            _dispatcherQueue.TryEnqueue(() =>
                            {
                                ScanSpeedText.Text = string.Format(Loc("SecurityPage_ScanSpeed_Format"), scanSpeed);
                            });
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
                        if (MainWindow.NowPage != "Security" | ThisId != ScanId)
                        {
                            break;
                        }
                        await Task.Delay(1, token);
                    }

                    UpdateScanItemStatus(currentItemIndex, Localizer.Get().GetLocalizedString("SecurityPage_Status_Completed"), false, _threatsFound);

                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        var settings = ApplicationData.Current.LocalSettings;
                        settings.Values["LastScanTime"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                        StatusText.Text = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_ScanCompleteFound"), _currentResults?.Count ?? 0);
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
                    StatusText.Text = Loc("SecurityPage_ScanCancelled");
                        ScanProgress.Visibility = Visibility.Collapsed;
                        ResumeScanButton.Visibility = Visibility.Collapsed;
                        StopRadarAnimation();
                    });
                }
                catch (Exception ex)
                {
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        LogText.AddNewLog(4, "Security - Failed", ex.Message);
                        StatusText.Text = string.Format(Loc("SecurityPage_ScanFailed_Format"), ex.Message);
                        ScanProgress.Visibility = Visibility.Collapsed;
                        PauseScanButton.Visibility = Visibility.Collapsed;
                        ResumeScanButton.Visibility = Visibility.Collapsed;
                        StopRadarAnimation();
                    });
                }
            });
            ScanButton.IsEnabled = true;
        }

        private void OnBackToVirusListClick(object sender, RoutedEventArgs e)
        {
            OnBackList(VirusList.Visibility != Visibility.Visible);
        }

        private void OnBackList(bool isShow)
        {
            VirusList.Visibility = isShow ? Visibility.Visible : Visibility.Collapsed;
            BackToVirusListButtonText.Text = isShow ? Localizer.Get().GetLocalizedString("SecurityPage_BackToVirusList_Hide") : Localizer.Get().GetLocalizedString("SecurityPage_BackToVirusList_Show");
            BackToVirusListButtonIcon.Glyph = isShow ? "\uED1A" : "\uE890";
        }

        private void OnPauseScanClick(object sender, RoutedEventArgs e)
        {
            _isPaused = true;
            ScanButton.IsEnabled = true;
            PauseScanButton.Visibility = Visibility.Collapsed;
            ResumeScanButton.Visibility = Visibility.Visible;
            UpdateScanAreaInfo(Localizer.Get().GetLocalizedString("SecurityPage_Area_Paused_Title"), Localizer.Get().GetLocalizedString("SecurityPage_Area_Paused_Detail"));
            PauseRadarAnimation();
        }

        private void OnResumeScanClick(object sender, RoutedEventArgs e)
        {
            _isPaused = false;
            ScanButton.IsEnabled = false;
            PauseScanButton.Visibility = Visibility.Visible;
            ResumeScanButton.Visibility = Visibility.Collapsed;
            UpdateScanAreaInfo(Localizer.Get().GetLocalizedString("SecurityPage_Area_Resume_Title"), Localizer.Get().GetLocalizedString("SecurityPage_Area_Resume_Detail"));
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

        private async void OnTrustClick(object sender, RoutedEventArgs e)
        {
            if ((sender as MenuFlyoutItem)?.Tag is not VirusRow row)
                return;
            
            // 确认对话框
            var confirmDialog = new ContentDialog
            {
                Title = Localizer.Get().GetLocalizedString("SecurityPage_TrustConfirm_Title"),
                Content = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_TrustConfirm_Content"), row.FilePath),
                PrimaryButtonText = Localizer.Get().GetLocalizedString("SecurityPage_TrustConfirm_Primary"),
                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                XamlRoot = this.XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
            };
            
            if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary)
            {
                try
                {
                    // 添加文件到信任区
                    bool success = Xdows.Protection.TrustManager.AddFileToTrust(row.FilePath, row.VirusName);
                    
                    // 显示结果
                    var resultDialog = new ContentDialog
                    {
                        Title = success ? 
                            Localizer.Get().GetLocalizedString("SecurityPage_TrustResult_Title") : 
                            Localizer.Get().GetLocalizedString("SecurityPage_TrustFailed_Title"),
                        Content = success ? 
                            string.Format(Localizer.Get().GetLocalizedString("SecurityPage_TrustResult_Content"), row.FilePath) :
                            Localizer.Get().GetLocalizedString("SecurityPage_TrustFailed_Content"),
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        XamlRoot = this.XamlRoot,
                        RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                        CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                    };
                    await resultDialog.ShowAsync();
                    
                    // 如果添加成功，从列表中移除
                    if (success && _currentResults != null)
                    {
                        var itemToRemove = _currentResults.FirstOrDefault(r => r.FilePath == row.FilePath && r.VirusName == row.VirusName);
                        if (itemToRemove != null)
                        {
                            _currentResults.Remove(itemToRemove);
                        }
                        _threatsFound--;
                        UpdateScanStats(_filesScanned, _filesSafe, _threatsFound);
                        StatusText.Text = string.Format(Loc("SecurityPage_ScanCompleteFound"), _currentResults?.Count ?? 0);
                    }
                }
                catch (Exception ex)
                {
                    await new ContentDialog
                    {
                        Title = Localizer.Get().GetLocalizedString("SecurityPage_TrustFailed_Title"),
                        Content = ex.Message,
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                        XamlRoot = this.XamlRoot,
                        CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                    }.ShowAsync();
                }
            }
        }

        private async void OnHandleClick(object sender, RoutedEventArgs e)
        {
            if ((sender as MenuFlyoutItem)?.Tag is not VirusRow row ||
                _currentResults is null) return;
            
            var dialog = new ContentDialog
            {
                Title = Localizer.Get().GetLocalizedString("SecurityPage_HandleConfirm_Title"),
                Content = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_HandleConfirm_Content"), row.FilePath),
                PrimaryButtonText = Localizer.Get().GetLocalizedString("SecurityPage_HandleConfirm_Primary"),
                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                XamlRoot = this.XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
            };
            
            if (await dialog.ShowAsync() == ContentDialogResult.Primary)
            {
                try
                {
                    bool handled = false;
                    string actionTaken = "";
                    
                    // 首先尝试加入隔离区
                    if (Xdows.Protection.QuarantineManager.AddToQuarantine(row.FilePath, row.VirusName))
                    {
                        actionTaken = Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_Quarantined");
                        handled = true;
                    }
                    // 如果隔离失败，尝试删除文件
                    else if (File.Exists(row.FilePath))
                    {
                        try
                        {
                            File.Delete(row.FilePath);
                            actionTaken = Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_Deleted");
                            handled = true;
                        }
                        catch
                        {
                            // 如果删除也失败，尝试修改文件名
                            try
                            {
                                string directory = Path.GetDirectoryName(row.FilePath) ?? "";
                                string fileName = Path.GetFileNameWithoutExtension(row.FilePath);
                                string extension = Path.GetExtension(row.FilePath);
                                string newFileName = $"{fileName}_virus_{DateTime.Now:yyyyMMddHHmmss}{extension}";
                                string newPath = Path.Combine(directory, newFileName);
                                
                                File.Move(row.FilePath, newPath);
                                actionTaken = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_Renamed"), newFileName);
                                handled = true;
                            }
                            catch
                            {
                                actionTaken = Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_Failed");
                            }
                        }
                    }
                    
                    // 显示处理结果
                    var resultDialog = new ContentDialog
                    {
                        Title = Localizer.Get().GetLocalizedString("SecurityPage_HandleResult_Title"),
                        Content = actionTaken,
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        XamlRoot = this.XamlRoot,
                        RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                        CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                    };
                    await resultDialog.ShowAsync();
                    
                    // 如果处理成功，从列表中移除
                    if (handled)
                    {
                        var itemToRemove = _currentResults.FirstOrDefault(r => r.FilePath == row.FilePath && r.VirusName == row.VirusName);
                        if (itemToRemove != null)
                        {
                            _currentResults.Remove(itemToRemove);
                        }
                        _threatsFound--;
                        UpdateScanStats(_filesScanned, _filesSafe, _threatsFound);
                        StatusText.Text = string.Format(Loc("SecurityPage_ScanCompleteFound"), _currentResults.Count);
                    }
                }
                catch (Exception ex)
                {
                    await new ContentDialog
                    {
                        Title = Localizer.Get().GetLocalizedString("SecurityPage_HandleFailed_Title"),
                        Content = ex.Message,
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
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
                bool isDetailsPause = PauseScanButton.Visibility == Visibility.Visible && PauseScanButton.IsEnabled;
                if (isDetailsPause)
                {
                    OnPauseScanClick(new object(), new RoutedEventArgs());
                }
                var fileInfo = new FileInfo(row.FilePath);
                var dialog = new ContentDialog
                {
                    Title = Loc("SecurityPage_Details_Title"),
                    Content = new ScrollViewer
                    {
                        Content = new StackPanel
                        {
                            Children =
                            {
                                new TextBlock { Text = Loc("SecurityPage_Details_FilePath"), Margin = new Thickness(0, 8, 0, 0) },
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
                                new TextBlock { Text = string.Format(Loc("SecurityPage_Details_VirusName"), row.VirusName), Margin = new Thickness(0, 8, 0, 0) },
                                new TextBlock { Text = string.Format(Loc("SecurityPage_Details_FileSize"), fileInfo.Length / 1024.0), Margin = new Thickness(0, 8, 0, 0) },
                                new TextBlock { Text = string.Format(Loc("SecurityPage_Details_CreationTime"), fileInfo.CreationTime), Margin = new Thickness(0, 8, 0, 0) },
                                new TextBlock { Text = string.Format(Loc("SecurityPage_Details_LastWriteTime"), fileInfo.LastWriteTime), Margin = new Thickness(0, 8, 0, 0) }
                            }
                        },
                        MaxHeight = 400
                    },
                    PrimaryButtonText = Loc("SecurityPage_Details_LocateButton"),
                    CloseButtonText = Loc("Button_Confirm"),
                    XamlRoot = this.XamlRoot,
                        RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                };
                if (await dialog.ShowAsync() == ContentDialogResult.Primary)
                {
                    try
                    {
                        string filePath = row.FilePath;
                        string? directoryPath = Path.GetDirectoryName(filePath);
                        string fileName = Path.GetFileName(filePath);

                        var psi = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "explorer.exe",
                        };
                        var safeFilePath = filePath.Replace("\"", "\\\"");
                        psi.Arguments = $"/select,\"{safeFilePath}\"";
                        System.Diagnostics.Process.Start(psi);
                    }
                    catch (Exception ex)
                    {
                        var dlg = new ContentDialog
                        {
                            Title = Loc("SecurityPage_LocateFailed_Title"),
                            Content = string.Format(Loc("SecurityPage_LocateFailed_Content"), ex.Message),
                            CloseButtonText = Loc("Button_Confirm"),
                            RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                            XamlRoot = this.XamlRoot,
                            CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                        };
                        await dlg.ShowAsync();
                    }
                }
                if (isDetailsPause)
                    OnResumeScanClick(new object(), new RoutedEventArgs());
            }
            catch (Exception ex)
            {
                try{
                    LogText.AddNewLog(4, "Security - FilesInfo - GetFailed", ex.Message);
                    var failDlg = new ContentDialog
                    {
                        Title = Loc("SecurityPage_GetFailed_Text"),
                        Content = ex.Message,
                        CloseButtonText = Loc("Button_Confirm"),
                        XamlRoot = this.XamlRoot,
                        RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                        CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                   };
                   await failDlg.ShowAsync();
                }catch{ }
            }
        }

        private async Task<string?> PickPathAsync(ScanMode mode)
        {
            if (mode == ScanMode.File)
            {
                using var dlg = new CommonOpenFileDialog
                {
                    Title = Loc("SecurityPage_SelectFile_Title"),
                    IsFolderPicker = false,
                    EnsurePathExists = true,
                };
                return dlg.ShowDialog() == CommonFileDialogResult.Ok ? dlg.FileName : null;
            }
            else
            {
                using var dlg = new CommonOpenFileDialog
                {
                    Title = Loc("SecurityPage_SelectFolder_Title"),
                    IsFolderPicker = true,
                    EnsurePathExists = true,
                };
                return dlg.ShowDialog() == CommonFileDialogResult.Ok ? dlg.FileName : null;
            }
        }

        private IReadOnlyList<string> EnumerateFiles(ScanMode mode, string? userPath, IReadOnlyList<string>? customPaths) =>
            mode switch
            {
                ScanMode.Quick => EnumerateQuickScanFiles().ToList(),
                ScanMode.Full => EnumerateFullScanFiles().ToList(),
                ScanMode.File => (userPath != null && System.IO.File.Exists(userPath))
                                  ? new[] { userPath }
                                  : Array.Empty<string>(),
                ScanMode.Folder => (userPath != null && Directory.Exists(userPath))
                                  ? SafeEnumerateFolder(userPath).ToList()
                                  : Array.Empty<string>(),
                ScanMode.More => customPaths?.SelectMany(p =>
                {
                    if (Directory.Exists(p))
                        return SafeEnumerateFolder(p);
                    else if (System.IO.File.Exists(p))
                        return new[] { p };
                    return Enumerable.Empty<string>();
                }).ToList() ?? new List<string>(),
                _ => Array.Empty<string>()
            };

        private IReadOnlyList<string> EnumerateFiles(ScanMode mode, string? userPath) =>
            EnumerateFiles(mode, userPath, null);

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
                    try { attr = System.IO.File.GetAttributes(entry); }
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

            var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".sys", ".com", ".scr", ".bat" };

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
                    else if (System.IO.File.Exists(entry) && scanned.Add(entry))
                    {
                        yield return entry;
                    }
                }
            }
        }
    }
}