using Microsoft.UI.Dispatching;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Windows.Storage;
using Windows.Storage.Pickers;
using WinRT.Interop;
using Xdows.ScanEngine;

namespace Xdows_Security
{
    public enum ScanMode { Quick, Full, File, Folder, More }
    public record VirusRow(string FilePath, string VirusName);

    public sealed partial class SecurityPage : Page
    {
        private CancellationTokenSource? _cts;
        private readonly DispatcherQueue _dispatcherQueue;
        private ObservableCollection<VirusRow>? _currentResults;

        public SecurityPage()
        {
            this.InitializeComponent();
            _dispatcherQueue = DispatcherQueue.GetForCurrentThread();
            PathText.Text = "扫描模式：未指定";
        }
        private void OnScanMenuClick(object sender, RoutedEventArgs e)
        {
            var settings = ApplicationData.Current.LocalSettings;
            bool UseLocalScan = settings.Values["LocalScan"] is bool && (bool)settings.Values["LocalScan"];
            bool UseCloudScan = settings.Values["CloudScan"] is bool && (bool)settings.Values["CloudScan"];
            if (!UseLocalScan && !UseCloudScan) {
                var dialog = new ContentDialog
                {
                    Title = "当前没有选择扫描引擎",
                    Content = "请转到 设置 - 引擎 来启用至少一个引擎。",
                    PrimaryButtonText = "确定",
                    XamlRoot = this.XamlRoot,
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
            _ = StartScanAsync(((MenuFlyoutItem)sender).Text, mode);
        }

        private async Task StartScanAsync(string displayName, ScanMode mode)
        {
            _cts?.Cancel();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            var settings = ApplicationData.Current.LocalSettings;
            bool showScanProgress = settings.Values["ShowScanProgress"] is bool && (bool)settings.Values["ShowScanProgress"];
            bool DeepScan = settings.Values["DeepScan"] is bool && (bool)settings.Values["DeepScan"];
            bool ExtraData = settings.Values["ExtraData"] is bool && (bool)settings.Values["ExtraData"];
            bool UseLocalScan = settings.Values["LocalScan"] is bool && (bool)settings.Values["LocalScan"];
            bool UseCloudScan = settings.Values["CloudScan"] is bool && (bool)settings.Values["CloudScan"];
            string Log = "Use";
            if (UseLocalScan) {
                Log += " LocalScan";
                if (DeepScan) { Log += "-DeepScan"; }
            }
            if (UseCloudScan)
            {
                Log += " CloudScan";
            }
            LogText.AddNewLog(1, "Security - StartScan", Log);
            _currentResults = new ObservableCollection<VirusRow>();
            _dispatcherQueue.TryEnqueue(() =>
            {
                ScanProgress.IsIndeterminate = !showScanProgress;
                VirusList.ItemsSource = _currentResults;
                VirusList.Visibility = Visibility.Visible;
                ScanProgress.Value = 0;
                ScanProgress.Visibility = Visibility.Visible;
                PathText.Text = $"扫描模式：{displayName}";
            });

            if (mode == ScanMode.More)
            {
                _dispatcherQueue.TryEnqueue(() =>
                {
                    ScanProgress.Visibility = Visibility.Collapsed;
                    StatusText.Text = "暂未实现";
                });
                return;
            }

            string? userPath = null;
            if (mode is ScanMode.File or ScanMode.Folder)
            {
                userPath = await PickPathAsync(mode);
                if (string.IsNullOrEmpty(userPath))
                {
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        ScanProgress.Visibility = Visibility.Collapsed;
                        StatusText.Text = "已取消选择";
                    });
                    return;
                }
            }

            ScanButton.IsEnabled = false;

            await Task.Run(async () =>
            {
                try
                {
                    var files = EnumerateFiles(mode, userPath);
                    int total = files.Count();
                    int finished = 0;

                    foreach (var file in files)
                    {
                        if (token.IsCancellationRequested) break;

                        _dispatcherQueue.TryEnqueue(() =>
                        {
                            LogText.AddNewLog(1, "Security - ScanFile", file);
                            StatusText.Text = $"正在扫描：{file}";
                        });
                        try
                        {
                            var Result = string.Empty;
                            if (UseLocalScan) {
                                var LocalResult = await Xdows.ScanEngine.ScanEngine.LocalScanAsync(file, DeepScan, ExtraData);
                                if (LocalResult != string.Empty)
                                {
                                    if (DeepScan) { Result = $"{LocalResult} with DeepScan"; } else { Result = LocalResult; }

                                }
                            }
                            if (UseCloudScan)
                            {
                                if (Result == string.Empty)
                                {
                                    var CloudResult = await Xdows.ScanEngine.ScanEngine.CloudScanAsync(file, App.GetCloudApiKey());
                                    if (CloudResult.result != "safe")
                                    {
                                        Result = CloudResult.result;
                                    }
                                }
                            }
                            if (Result != string.Empty)
                            {
                                LogText.AddNewLog(1, "Security - Find", Result);
                                _dispatcherQueue.TryEnqueue(() => _currentResults!.Add(new VirusRow(file, Result)));
                            }
                            else
                            {
                                LogText.AddNewLog(1, "Security - Find", "Is Safe");
                            }

                        }
                        catch
                        {
                            // 跳过单个文件错误
                        }


                        finished++;
                        if (showScanProgress)
                        {
                            var percent = total == 0 ? 100 : (double)finished / total * 100;
                            _dispatcherQueue.TryEnqueue(() => ScanProgress.Value = percent);
                        }
                        await Task.Delay(1, token);
                    }

                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        StatusText.Text = $"扫描完成，共发现 {_currentResults.Count} 个威胁";
                        ScanProgress.Visibility = Visibility.Collapsed;
                    });
                }
                catch (OperationCanceledException)
                {
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        StatusText.Text = "扫描已取消";
                        ScanProgress.Visibility = Visibility.Collapsed;
                    });
                }
                catch (Exception ex)
                {
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        LogText.AddNewLog(1, "Security - Failed", ex.Message);
                        StatusText.Text = $"扫描失败：{ex.Message}";
                        ScanProgress.Visibility = Visibility.Collapsed;
                    });
                }
            });
            ScanButton.IsEnabled = true;
        }
        private async void VirusList_DoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
        {
            if ((sender as ListView)?.SelectedItem is VirusRow row)
            {
                await ShowDetailsDialog(row);
            }
        }

        #region 右键菜单
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
                Title = "你需要删除这个文件吗？",
                Content = $"确定要删除这个文件吗？\n{row.FilePath}\n这将不会经过回收站，可能需要第三方软件才能恢复。",
                PrimaryButtonText = "删除",
                CloseButtonText = "取消",
                XamlRoot = this.XamlRoot,
                PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
            };
            if (await dialog.ShowAsync() == ContentDialogResult.Primary)
            {
                try
                {
                    File.Delete(row.FilePath);
                    _currentResults.Remove(row);   // UI 立即刷新
                    StatusText.Text = $"扫描完成，共发现 {_currentResults.Count} 个威胁";
                }
                catch (Exception ex)
                {
                    await new ContentDialog
                    {
                        Title = "删除失败",
                        Content = ex.Message,
                        CloseButtonText = "确定",
                        XamlRoot = this.XamlRoot
                    }.ShowAsync();
                }
            }
        }

        private async Task ShowDetailsDialog(VirusRow row)
        {
            var dlg = new ContentDialog
            {
                Title = "文件详细信息",
                Content = new StackPanel
                {
                    Spacing = 8,
                    Children =
                    {
                        new TextBlock{Text="文件路径：",FontWeight=FontWeights.SemiBold},
                        new TextBox{Text=row.FilePath,IsReadOnly=true,TextWrapping=TextWrapping.Wrap},
                        new TextBlock{Text="威胁名称：",FontWeight=FontWeights.SemiBold},
                        new TextBlock{Text=row.VirusName}
                    }
                },
                PrimaryButtonText = "确定",
                XamlRoot = this.XamlRoot,
                PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
            };
            await dlg.ShowAsync();
        }
        #endregion

        #region 辅助
        private async Task<string?> PickPathAsync(ScanMode mode)
        {
            var hwnd = WindowNative.GetWindowHandle(App.MainWindow);
            if (mode == ScanMode.File)
            {
                var picker = new FileOpenPicker { ViewMode = PickerViewMode.List, SuggestedStartLocation = PickerLocationId.ComputerFolder };
                picker.FileTypeFilter.Add("*");
                InitializeWithWindow.Initialize(picker, hwnd);
                return (await picker.PickSingleFileAsync())?.Path;
            }
            if (mode == ScanMode.Folder)
            {
                var picker = new FolderPicker { SuggestedStartLocation = PickerLocationId.ComputerFolder };
                picker.FileTypeFilter.Add("*");
                InitializeWithWindow.Initialize(picker, hwnd);
                return (await picker.PickSingleFolderAsync())?.Path;
            }
            return null;
        }

        private static IEnumerable<string> EnumerateFiles(ScanMode mode, string? userPath = null) =>
            mode switch
            {
                ScanMode.Quick => SafeEnumerateFiles(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)),
                ScanMode.Full => DriveInfo.GetDrives()
                                          .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
                                          .SelectMany(d => SafeEnumerateFiles(d.RootDirectory.FullName)),
                ScanMode.File => userPath is null ? Array.Empty<string>() : new[] { userPath },
                ScanMode.Folder => userPath is null ? Array.Empty<string>() : SafeEnumerateFiles(userPath),
                _ => Array.Empty<string>()
            };

        private static IEnumerable<string> SafeEnumerateFiles(string root, bool recursive = true)
        {
            var allow = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                 ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".doc", ".docx"
            };
            var dirs = new Stack<string>();
            dirs.Push(root);

            while (dirs.Count > 0)
            {
                var cur = dirs.Pop();

                foreach (var f in Directory.EnumerateFiles(cur))
                    if (allow.Contains(Path.GetExtension(f)))
                        yield return f;

                if (!recursive) continue;
                foreach (var d in Directory.EnumerateDirectories(cur))
                    dirs.Push(d);
            }
        }
        #endregion
    }

}