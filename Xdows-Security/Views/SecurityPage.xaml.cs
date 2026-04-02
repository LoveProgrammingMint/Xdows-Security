using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Compatibility.Windows.Storage;
using Helper;
using Microsoft.UI;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.Windows.Storage.Pickers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using TrustQuarantine;
using WinUI3Localizer;

namespace Xdows_Security.Views
{
    public enum ScanMode { Quick, Full, File, Folder, More }
    public partial class VirusRow : ObservableObject
    {
        [ObservableProperty]
        public partial String FilePath { get; set; }

        [ObservableProperty]
        public partial String VirusName { get; set; }

        public IRelayCommand? ShowDetailsCommand { get; set; }
        public IRelayCommand? TrustCommand { get; set; }
        public IRelayCommand? HandleCommand { get; set; }
    }

    public record ScanItem
    {
        public String ItemName { get; set; } = String.Empty;
        public String IconGlyph { get; set; } = "&#xE721;";
        public SolidColorBrush IconColor { get; set; } = new SolidColorBrush(Colors.Gray);
        public String StatusText { get; set; } = Localizer.Get().GetLocalizedString("SecurityPage_Status_Waiting");
        public Int32 ThreatCount { get; set; } = 0;
        public Visibility ThreatCountVisibility { get; set; } = Visibility.Collapsed;
        public SolidColorBrush ThreatCountBackground { get; set; } = new SolidColorBrush(Colors.Red);
    }

    public partial class MoreScanItem : INotifyPropertyChanged
    {
        private String _path = String.Empty;
        private Boolean _isFolder;

        public String Path
        {
            get => _path;
            set { _path = value; OnPropertyChanged(); }
        }

        public Boolean IsFolder
        {
            get => _isFolder;
            set { _isFolder = value; OnPropertyChanged(); OnPropertyChanged(nameof(IconGlyph)); }
        }

        public String IconGlyph => _isFolder ? "\uE8B7" : "\uE8A5";

        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] String name = null!)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    public sealed partial class SecurityPage : Page
    {
        private CancellationTokenSource? _cts;
        private readonly DispatcherQueue _dispatcherQueue;
        private ObservableCollection<VirusRow>? CurrentResults { set; get; }
        private List<ScanItem>? _scanItems;
        private Boolean _isPaused = false;
        private Int32 _filesScanned = 0;
        private Int32 _filesSafe = 0;
        private Int32 _threatsFound = 0;
        private Int32 ScanId = 0;
        private ContentDialog? _moreScanDialog;
        private IRelayCommand? _showDetailsCommand;
        private IRelayCommand? _trustCommand;
        private IRelayCommand? _handleCommand;
        private readonly Dictionary<String, List<(String EntryPath, String VirusName)>> _zipFileThreats = [];

        public SecurityPage()
        {
            this.InitializeComponent();
            _dispatcherQueue = DispatcherQueue.GetForCurrentThread();
            PathText.Text = Localizer.Get().GetLocalizedString("SecurityPage_PathText_Default");
            ScanSpeedText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_ScanSpeed_Format"), 0.0);
            FilesScannedText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_FilesScanned_Format"), 0);
            FilesSafeText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_FilesSafe_Format"), 0);
            ThreatsFoundText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_ThreatsFound_Format"), 0);
            InitializeCommands();
            InitializeScanItems();
        }

        private void InitializeCommands()
        {
            _showDetailsCommand = new RelayCommand<VirusRow>(async (row) =>
            {
                await ShowDetailsDialog(row);
            });

            _trustCommand = new RelayCommand<VirusRow>(async (row) =>
            {
                await OnTrustClickInternal(row);
            });

            _handleCommand = new RelayCommand<VirusRow>(async (row) =>
            {
                await OnHandleClickInternal(row);
            });
        }

        private void AddVirusResult(String filePath, String virusName)
        {
            VirusRow row = new()
            {
                FilePath = filePath,
                VirusName = virusName,
                ShowDetailsCommand = _showDetailsCommand,
                TrustCommand = _trustCommand,
                HandleCommand = _handleCommand
            };

            CurrentResults?.Add(row);
        }

        private async Task OnTrustClickInternal(VirusRow? row)
        {
            if (row is null) return;

            ContentDialog confirmDialog = new()
            {
                Title = Localizer.Get().GetLocalizedString("SecurityPage_TrustConfirm_Title"),
                Content = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_TrustConfirm_Content"), row.FilePath),
                PrimaryButtonText = Localizer.Get().GetLocalizedString("SecurityPage_TrustConfirm_Primary"),
                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                XamlRoot = this.XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                DefaultButton = ContentDialogButton.Primary
            };

            if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary)
            {
                try
                {
                    Boolean success = await TrustManager.AddToTrust(row.FilePath);

                    ContentDialog resultDialog = new()
                    {
                        Title = success ?
                            Localizer.Get().GetLocalizedString("SecurityPage_TrustResult_Title") :
                            Localizer.Get().GetLocalizedString("SecurityPage_TrustFailed_Title"),
                        Content = success ?
                            String.Format(Localizer.Get().GetLocalizedString("SecurityPage_TrustResult_Content"), row.FilePath) :
                            Localizer.Get().GetLocalizedString("SecurityPage_TrustFailed_Content"),
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        XamlRoot = this.XamlRoot,
                        RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                        DefaultButton = ContentDialogButton.Close
                    };
                    await resultDialog.ShowAsync();

                    if (success && CurrentResults != null)
                    {
                        VirusRow? itemToRemove = CurrentResults.FirstOrDefault(r => r.FilePath == row.FilePath && r.VirusName == row.VirusName);
                        if (itemToRemove != null)
                        {
                            CurrentResults.Remove(itemToRemove);
                        }
                        _threatsFound--;
                        UpdateScanStats(_filesScanned, _filesSafe, _threatsFound);
                        StatusText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_ScanCompleteFound"), CurrentResults?.Count ?? 0);
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
                        DefaultButton = ContentDialogButton.Close
                    }.ShowAsync();
                }
            }
        }

        private async Task OnHandleClickInternal(VirusRow? row)
        {
            if (CurrentResults is null || row is null) return;

            String displayPath = row.FilePath;
            String? zipPath = null;
            String? entryPath = null;

            Int32 zipIndex = displayPath.IndexOf(".zip\\", StringComparison.OrdinalIgnoreCase);
            if (zipIndex > 0)
            {
                zipPath = displayPath[..(zipIndex + 4)];
                entryPath = displayPath[(zipIndex + 5)..];
            }

            var progressContent = new StackPanel
            {
                Spacing = 16,
                HorizontalAlignment = HorizontalAlignment.Center,
                Children =
                   {
                       new ProgressRing { IsActive = true, Width = 40, Height = 40 },
                       new TextBlock
                         {
                            Text = Localizer.Get().GetLocalizedString("SecurityPage_HandleProcessing"),
                            HorizontalAlignment = HorizontalAlignment.Center,
                            Style = Application.Current.Resources["BodyTextBlockStyle"] as Style
                         }
                   }
            };

            var dialog = new ContentDialog
            {
                Title = Localizer.Get().GetLocalizedString("SecurityPage_HandleConfirm_Title"),
                Content = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_HandleConfirm_Content"), displayPath),
                PrimaryButtonText = Localizer.Get().GetLocalizedString("SecurityPage_HandleConfirm_Primary"),
                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                XamlRoot = this.XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                DefaultButton = ContentDialogButton.Primary
            };

            dialog.PrimaryButtonClick += async (s, args) =>
            {
                args.Cancel = true;

                dialog.PrimaryButtonText = null;
                dialog.CloseButtonText = null;
                dialog.Content = progressContent;

                try
                {
                    var result = await Task.Run(async () =>
                    {
                        Boolean handled = false;
                        String actionTaken = "";

                        if (zipPath != null && entryPath != null && _zipFileThreats.ContainsKey(zipPath))
                        {
                            var threatsInZip = _zipFileThreats[zipPath];
                            var entriesToDelete = new List<String>();
                            Int32 quarantinedCount = 0;

                            foreach (var (EntryPath, VirusName) in threatsInZip)
                            {
                                if (EntryPath == entryPath || threatsInZip.Any(t => t.EntryPath.StartsWith(entryPath + "\\")))
                                {
                                    entriesToDelete.Add(EntryPath);
                                }
                            }

                            if (entriesToDelete.Count > 0)
                            {
                                foreach (var entry in entriesToDelete)
                                {
                                    try
                                    {
                                        var fileData = await ZipScanner.ExtractEntryAsync(zipPath, entry);
                                        if (fileData != null && fileData.Length > 0)
                                        {
                                            var threatInfo = threatsInZip.FirstOrDefault(t => t.EntryPath == entry);
                                            String virusName = threatInfo.VirusName ?? row.VirusName ?? "Unknown";
                                            String sourcePath = Path.GetDirectoryName(zipPath) + "\\" + Path.GetFileName(entry);

                                            LogText.AddNewLog(LogText.LogLevel.INFO, "Security - QuarantineZipEntry", $"Quarantining {sourcePath} from {zipPath}, size: {fileData.Length} bytes");

                                            if (await QuarantineManager.AddToQuarantineFromBytes(fileData, sourcePath, virusName, false))
                                            {
                                                quarantinedCount++;
                                                LogText.AddNewLog(LogText.LogLevel.INFO, "Security - QuarantineZipEntry", $"Successfully quarantined {sourcePath}");
                                            }
                                            else
                                            {
                                                LogText.AddNewLog(LogText.LogLevel.WARN, "Security - QuarantineZipEntry", $"Failed to quarantine {sourcePath}");
                                            }
                                        }
                                        else
                                        {
                                            LogText.AddNewLog(LogText.LogLevel.WARN, "Security - QuarantineZipEntry", $"Failed to extract {entry} from {zipPath}");
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        LogText.AddNewLog(LogText.LogLevel.ERROR, "Security - QuarantineZipEntry", $"Exception quarantining {entry}: {ex.Message}");
                                    }
                                }

                                Int32 deletedCount = 0;
                                if (quarantinedCount > 0)
                                {
                                    deletedCount = await ZipScanner.DeleteMultipleEntriesFromZipAsync(zipPath, entriesToDelete);
                                    LogText.AddNewLog(LogText.LogLevel.INFO, "Security - DeleteZipEntries", $"Deleted {deletedCount} entries from {zipPath}");
                                }

                                if (deletedCount > 0 || quarantinedCount > 0)
                                {
                                    actionTaken = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_ZipEntriesQuarantined"), quarantinedCount, deletedCount);
                                    handled = true;
                                }
                            }
                        }
                        else if (await QuarantineManager.AddToQuarantine(row.FilePath, row.VirusName))
                        {
                            actionTaken = Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_Quarantined");
                            handled = true;
                        }
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
                                try
                                {
                                    if (await QuarantineManager.AddToQuarantine(row.FilePath, row.VirusName))
                                    {
                                        actionTaken = Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_Quarantined");
                                        handled = true;
                                    }
                                    else
                                    {
                                        actionTaken = Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_Failed");
                                    }
                                }
                                catch
                                {
                                    actionTaken = Localizer.Get().GetLocalizedString("SecurityPage_HandleAction_Failed");
                                }
                            }
                        }

                        return (handled, actionTaken, zipPath, entryPath);
                    });

                    if (result.handled && result.zipPath != null && result.entryPath != null)
                    {
                        var entriesToDelete = new List<String>();
                        if (_zipFileThreats.ContainsKey(result.zipPath))
                        {
                            var threatsInZip = _zipFileThreats[result.zipPath];
                            foreach (var (EntryPath, VirusName) in threatsInZip)
                            {
                                if (EntryPath == result.entryPath || threatsInZip.Any(t => t.EntryPath.StartsWith(result.entryPath + "\\")))
                                {
                                    entriesToDelete.Add(EntryPath);
                                }
                            }

                            foreach (var entry in entriesToDelete)
                            {
                                VirusRow? itemToRemove = CurrentResults.FirstOrDefault(r => r.FilePath == $"{result.zipPath}\\{entry}");
                                if (itemToRemove != null)
                                {
                                    CurrentResults.Remove(itemToRemove);
                                    _threatsFound--;
                                }
                            }

                            _zipFileThreats.Remove(result.zipPath);
                        }
                    }

                    dialog.Content = new TextBlock
                    {
                        Text = result.actionTaken,
                        TextWrapping = TextWrapping.Wrap
                    };

                    dialog.CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm");
                    dialog.DefaultButton = ContentDialogButton.Close;

                    if (result.handled)
                    {
                        UpdateScanStats(_filesScanned, _filesSafe, _threatsFound);
                        StatusText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_ScanCompleteFound"), CurrentResults.Count);
                    }
                }
                catch (Exception ex)
                {
                    dialog.Content = new TextBlock
                    {
                        Text = ex.Message,
                        TextWrapping = TextWrapping.Wrap
                    };
                    dialog.Title = Localizer.Get().GetLocalizedString("SecurityPage_HandleFailed_Title");
                    dialog.CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm");
                }
            };

            await dialog.ShowAsync();
        }
        private void InitializeScanItems()
        {
            _scanItems =
            [
                new() { ItemName = Localizer.Get().GetLocalizedString("SecurityPage_ScanItem_System"), IconGlyph = "&#xE721;", StatusText = Localizer.Get().GetLocalizedString("SecurityPage_Status_Waiting") },
                new() { ItemName = Localizer.Get().GetLocalizedString("SecurityPage_ScanItem_Memory"), IconGlyph = "&#xE896;", StatusText = Localizer.Get().GetLocalizedString("SecurityPage_Status_Waiting") },
                new() { ItemName = Localizer.Get().GetLocalizedString("SecurityPage_ScanItem_Startup"), IconGlyph = "&#xE812;", StatusText = Localizer.Get().GetLocalizedString("SecurityPage_Status_Waiting") },
                new() { ItemName = Localizer.Get().GetLocalizedString("SecurityPage_ScanItem_UserDocs"), IconGlyph = "&#xE8A5;", StatusText = Localizer.Get().GetLocalizedString("SecurityPage_Status_Waiting") }
            ];
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

        private void UpdateScanItemStatus(Int32 itemIndex, String status, Boolean isActive, Int32 threatCount = 0)
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                try
                {
                    if (_scanItems != null && itemIndex < _scanItems.Count)
                    {
                        ScanItem item = _scanItems[itemIndex];
                        item.StatusText = status;
                        item.IconColor = new SolidColorBrush(isActive ? Colors.DodgerBlue : Colors.Gray);
                        item.ThreatCount = threatCount;
                        item.ThreatCountVisibility = threatCount > 0 ? Visibility.Visible : Visibility.Collapsed;
                    }
                }
                catch { }
            });
        }

        private void UpdateScanStats(Int32 filesScanned, Int32 filesSafe, Int32 threatsFound)
        {
            _dispatcherQueue.TryEnqueue(() =>
            {
                _filesScanned = filesScanned;
                _filesSafe = filesSafe;
                _threatsFound = threatsFound;
                try
                {
                    FilesScannedText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_FilesScanned_Format"), filesScanned);
                    FilesSafeText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_FilesSafe_Format"), filesSafe);
                    ThreatsFoundText.Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_ThreatsFound_Format"), threatsFound);
                }
                catch { }
            });
        }

        private async void OnScanMenuClick(Object sender, RoutedEventArgs e)
        {
            ApplicationDataContainer settings = ApplicationData.Current.LocalSettings;
            Boolean UseLocalScan = (settings.Values["LocalScan"] as Boolean?).GetValueOrDefault();
            Boolean UseCzkCloudScan = (settings.Values["CzkCloudScan"] as Boolean?).GetValueOrDefault();
            Boolean UseCloudScan = (settings.Values["CloudScan"] as Boolean?).GetValueOrDefault();
            Boolean UseSouXiaoScan = (settings.Values["SouXiaoScan"] as Boolean?).GetValueOrDefault();
            Boolean UseModelScan = (settings.Values["ModelScan"] as Boolean?).GetValueOrDefault();
            if (!UseLocalScan && !UseCzkCloudScan && !UseSouXiaoScan && !UseCloudScan && !UseModelScan)
            {
                ContentDialog dialog = new()
                {
                    Title = Localizer.Get().GetLocalizedString("SecurityPage_NoEngine_Title"),
                    Content = Localizer.Get().GetLocalizedString("SecurityPage_NoEngine_Content"),
                    PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    DefaultButton = ContentDialogButton.Primary
                };
                _ = dialog.ShowAsync();
                return;
            }

            if (sender is not MenuFlyoutItem { Tag: String tag }) return;
            ScanMode mode = tag switch
            {
                "Quick" => ScanMode.Quick,
                "Full" => ScanMode.Full,
                "File" => ScanMode.File,
                "Folder" => ScanMode.Folder,
                _ => ScanMode.More
            };

            if (mode == ScanMode.More)
            {
                IReadOnlyList<String> paths = await ShowMoreScanDialogAsync();
                if (paths.Count > 0)
                {
                    await StartScanAsync(Localizer.Get().GetLocalizedString("SecurityPage_ScanMenu_More"), ScanMode.More, paths);
                }
                return;
            }

            await StartScanAsync(((MenuFlyoutItem)sender).Text, mode);
        }

        private static IEnumerable<String> EnumerateFilesStreaming(ScanMode mode, String? userPath, IReadOnlyList<String>? customPaths)
        {
            switch (mode)
            {
                case ScanMode.Quick:
                    foreach (String f in GetEnumerateQuickScanFiles()) yield return f;
                    yield break;
                case ScanMode.Full:
                    foreach (DriveInfo drive in DriveInfo.GetDrives())
                    {
                        if (!drive.IsReady || drive.DriveType is DriveType.CDRom or DriveType.Network)
                            continue;
                        foreach (String file in SafeEnumerateFiles(drive.RootDirectory.FullName, new HashSet<String>(StringComparer.OrdinalIgnoreCase)))
                            yield return file;
                    }
                    yield break;
                case ScanMode.File:
                    if (userPath != null && System.IO.File.Exists(userPath)) yield return userPath;
                    yield break;
                case ScanMode.Folder:
                    if (userPath != null && Directory.Exists(userPath))
                    {
                        foreach (String f in SafeEnumerateFolder(userPath)) yield return f;
                    }
                    yield break;
                case ScanMode.More:
                    if (customPaths != null)
                    {
                        foreach (String p in customPaths)
                        {
                            if (Directory.Exists(p))
                            {
                                foreach (String f in SafeEnumerateFolder(p)) yield return f;
                            }
                            else if (System.IO.File.Exists(p))
                            {
                                yield return p;
                            }
                        }
                    }
                    yield break;
                default:
                    yield break;
            }
        }

        private async Task<IReadOnlyList<String>> ShowMoreScanDialogAsync()
        {
            ObservableCollection<MoreScanItem> items = [];
            ListView listView = new()
            {
                ItemTemplate = Resources["MoreScanListTemplate"] as DataTemplate,
                ItemsSource = items,
                Height = 240
            };

            Button browseFolderButton = new() { Content = Localizer.Get().GetLocalizedString("SecurityPage_More_BrowseFolder") };
            browseFolderButton.Click += OnMoreScanBrowseFolderClick;
            Button browseFileButton = new() { Content = Localizer.Get().GetLocalizedString("SecurityPage_More_BrowseFile") };
            browseFileButton.Click += OnMoreScanBrowseFileClick;
            Button removeFileButton = new() { Content = Localizer.Get().GetLocalizedString("SecurityPage_More_RemoveItem") };
            removeFileButton.Click += OnMoreScanRemovePathClick;
            Button clearButton = new() { Content = Localizer.Get().GetLocalizedString("SecurityPage_More_ClearAll"), IsEnabled = false };
            clearButton.Click += OnMoreScanClearClick;

            items.CollectionChanged += (s, e) =>
            {
                clearButton.IsEnabled = items.Count > 0;
            };

            Grid contentGrid = new() { RowSpacing = 12 };
            contentGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            contentGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            Grid.SetRow(listView, 0);

            StackPanel buttonPanel = new()
            {
                Orientation = Orientation.Horizontal,
                Spacing = 8,
                Children = { browseFolderButton, browseFileButton, removeFileButton, clearButton }
            };
            Grid.SetRow(buttonPanel, 1);

            contentGrid.Children.Add(listView);
            contentGrid.Children.Add(buttonPanel);

            _moreScanDialog = new ContentDialog
            {
                Title = Localizer.Get().GetLocalizedString("SecurityPage_MoreScan_Title"),
                Content = contentGrid,
                PrimaryButtonText = Localizer.Get().GetLocalizedString("SecurityPage_StartScanButton"),
                CloseButtonText = Localizer.Get().GetLocalizedString("Button_Cancel"),
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = this.XamlRoot,
                RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                Width = 600,
                Height = 450
            };

            ContentDialogResult result = await _moreScanDialog.ShowAsync();
            _moreScanDialog = null;

            if (result == ContentDialogResult.Primary)
            {
                return [.. items.Select(i => i.Path)];
            }
            return [];
        }

        private void OnMoreScanRemovePathClick(Object sender, RoutedEventArgs e)
        {
            ListView? listView = FindChild<ListView>(_moreScanDialog?.Content as DependencyObject);
            if (listView?.SelectedItem is MoreScanItem item)
            {
                if (listView.ItemsSource is ObservableCollection<MoreScanItem> items)
                {
                    items.Remove(item);
                }
            }
        }

        private async void OnMoreScanBrowseFolderClick(Object sender, RoutedEventArgs e)
        {
            string? folder = await PickPathAsync(ScanMode.Folder);
            if (folder is null) return;
            await AddPathToMoreScanList(folder, true);
        }

        private async void OnMoreScanBrowseFileClick(Object sender, RoutedEventArgs e)
        {
            string? file = await PickPathAsync(ScanMode.File);
            if (file is null) return;
            await AddPathToMoreScanList(file, false);
        }

        private async Task AddPathToMoreScanList(String path, Boolean isFolder)
        {
            ListView? listView = FindChild<ListView>(_moreScanDialog?.Content as DependencyObject);
            if (listView?.ItemsSource is not ObservableCollection<MoreScanItem> items) return;

            HashSet<String> existingPaths = new(items.Select(i => i.Path), StringComparer.OrdinalIgnoreCase);

            if (existingPaths.Contains(path))
            {
                ContentDialog dup = new()
                {
                    Title = Localizer.Get().GetLocalizedString("SecurityPage_DuplicatePath_Title"),
                    Content = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_DuplicatePath_Content"), path),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
                };
                _ = dup.ShowAsync();
                return;
            }

            items.Add(new MoreScanItem { Path = path, IsFolder = isFolder });
        }

        private void OnMoreScanClearClick(Object sender, RoutedEventArgs e)
        {
            ListView? listView = FindChild<ListView>(_moreScanDialog?.Content as DependencyObject);
            if (listView?.ItemsSource is ObservableCollection<MoreScanItem> items)
            {
                items.Clear();
            }
        }

        private T? FindChild<T>(DependencyObject? parent) where T : DependencyObject
        {
            if (parent == null) return null;

            for (Int32 i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                DependencyObject child = VisualTreeHelper.GetChild(parent, i);
                if (child is T typedChild)
                    return typedChild;

                T? result = FindChild<T>(child);
                if (result != null)
                    return result;
            }
            return null;
        }

        private record ScanResult(String EngineName, String? VirusInfo);

        // Run configured scan engines against a single file and return the first detection (if any).
        private async Task<ScanResult> RunScansOnFileAsync(String filePath, Boolean deepScan, Boolean extraData,
            Boolean useLocalScan, Boolean useCloudScan, Boolean useCzkCloudScan, Boolean useSouXiaoScan, Boolean useModelScan,
            Helper.ScanEngine.SouXiaoEngineScan? souXiaoEngine, Helper.ScanEngine.ModelEngineScan? modelEngine,
            String czkApiKey, CancellationToken token)
        {
            try
            {
                if (TrustManager.IsPathTrusted(filePath))
                    return new ScanResult(String.Empty, null);

                var scanTasks = new List<Task<ScanResult>>();

                if (useSouXiaoScan && souXiaoEngine != null)
                {
                    scanTasks.Add(Task.Run(() =>
                    {
                        (Boolean isVirus, String result) = souXiaoEngine.ScanFile(filePath);
                        return new ScanResult("SouXiao", isVirus ? result : null);
                    }));
                }

                if (useModelScan && modelEngine != null)
                {
                    scanTasks.Add(Task.Run(() =>
                    {
                        (Boolean isVirus, String result) = ScanEngine.ModelEngineScan.ScanFile(filePath);
                        return new ScanResult("Xdows-Model", isVirus ? result : null);
                    }));
                }

                if (useLocalScan)
                {
                    scanTasks.Add(Helper.ScanEngine.LocalScanAsync(filePath, deepScan, extraData)
                        .ContinueWith(t =>
                        {
                            String localResult = t.Result;
                            String? info = !String.IsNullOrEmpty(localResult) ? (deepScan ? $"{localResult} with DeepScan" : localResult) : null;
                            return new ScanResult("Local", info);
                        }, TaskScheduler.Default));
                }

                if (useCloudScan)
                {
                    scanTasks.Add(Helper.ScanEngine.CloudScanAsync(filePath)
                        .ContinueWith(t =>
                        {
                            (Int32? statusCode, String? result) = t.Result;
                            String? info = (result == "virus_file") ? "MEMZUAC.Cloud.VirusFile" : null;
                            return new ScanResult("Cloud", info);
                        }, TaskScheduler.Default));
                }

                if (useCzkCloudScan)
                {
                    scanTasks.Add(Helper.ScanEngine.CzkCloudScanAsync(filePath, czkApiKey)
                        .ContinueWith(t =>
                        {
                            (Int32? statusCode, String? result) = t.Result;
                            String? info = (result != "safe") ? (result ?? String.Empty) : null;
                            return new ScanResult("CzkCloud", info);
                        }, TaskScheduler.Default));
                }

                if (scanTasks.Count == 0)
                    return new ScanResult(String.Empty, null);

                var allTask = Task.WhenAll(scanTasks);
                while (!allTask.IsCompleted)
                {
                    if (token.IsCancellationRequested) break;
                    if (_isPaused)
                    {
                        await Task.Delay(100, token);
                        continue;
                    }
                    await Task.WhenAny(allTask, Task.Delay(100, token));
                }

                if (allTask.IsCompleted && !allTask.IsFaulted)
                {
                    foreach (var r in allTask.Result)
                    {
                        if (!String.IsNullOrEmpty(r.VirusInfo))
                            return r;
                    }
                }

                return new ScanResult(String.Empty, null);
            }
            catch (OperationCanceledException) { return new ScanResult(String.Empty, null); }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.WARN, "Security - RunScansOnFileFailed", ex.Message);
                return new ScanResult(String.Empty, null);
            }
        }

        private async Task ScanZipFileAsync(String zipPath, Boolean scanNested, Boolean deepScan, Boolean extraData, Boolean useLocalScan, Boolean useCloudScan, Boolean useCzkCloudScan, Boolean useSouXiaoScan, Boolean useModelScan, Helper.ScanEngine.SouXiaoEngineScan? souXiaoEngine, Helper.ScanEngine.ModelEngineScan? modelEngine, String czkApiKey, CancellationToken token)
        {
            try
            {
                var entries = await ZipScanner.ReadZipEntriesAsync(zipPath, scanNested);

                foreach (var (entryPath, data) in entries)
                {
                    // respect pause and cancellation
                    while (_isPaused && !token.IsCancellationRequested)
                        await Task.Delay(100, token);
                    if (token.IsCancellationRequested) break;

                    string displayPath = $"{zipPath}\\{entryPath}";
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        LogText.AddNewLog(LogText.LogLevel.INFO, "Security - ScanFile", displayPath);
                        try { StatusText.Text = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_Status_Scanning"), displayPath); } catch { }
                    });

                    string tempFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                    try
                    {
                        await File.WriteAllBytesAsync(tempFile, data, token);

                        if (TrustManager.IsPathTrusted(tempFile))
                        {
                            _filesSafe++;
                            continue;
                        }

                        // Run all configured scans on the extracted entry file
                        var scanRes = await RunScansOnFileAsync(tempFile, deepScan, extraData, useLocalScan, useCloudScan, useCzkCloudScan, useSouXiaoScan, useModelScan, souXiaoEngine, modelEngine, czkApiKey, token);
                        string? virusResult = scanRes.VirusInfo;
                        if (!String.IsNullOrEmpty(virusResult))
                        {
                            Statistics.ScansQuantity += 1;
                            Statistics.VirusQuantity += 1;

                            if (!_zipFileThreats.ContainsKey(zipPath))
                                _zipFileThreats[zipPath] = new List<(string, string)>();

                            _zipFileThreats[zipPath].Add((entryPath, virusResult));

                            _dispatcherQueue.TryEnqueue(() =>
                            {
                                AddVirusResult($"{zipPath}\\{entryPath}", virusResult);
                                BackToVirusListButton.Visibility = Visibility.Visible;
                            });

                            _threatsFound++;
                            LogText.AddNewLog(LogText.LogLevel.INFO, "Security - Find", $"ZIP Entry: {entryPath} - {virusResult}");
                        }
                        else
                        {
                            _filesSafe++;
                        }
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception ex)
                    {
                        LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ScanZipEntryFailed", ex.Message);
                    }
                    finally
                    {
                        try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ScanZipFailed", ex.Message);
            }
        }

        private async Task StartScanAsync(String displayName, ScanMode mode, IReadOnlyList<String>? customPaths = null)
        {
            _cts?.Cancel();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            _isPaused = false;
            _zipFileThreats.Clear();

            var settings = ApplicationData.Current.LocalSettings;
            bool showScanProgress = settings.Values["ShowScanProgress"] as bool? ?? false;
            string scanIndexMode = settings.Values["ScanIndexMode"] as string ?? "Parallel";
            bool DeepScan = settings.Values["DeepScan"] as bool? ?? false;
            bool ExtraData = settings.Values["ExtraData"] as bool? ?? false;
            bool UseLocalScan = settings.Values["LocalScan"] as bool? ?? false;
            bool UseCzkCloudScan = settings.Values["CzkCloudScan"] as bool? ?? false;
            bool UseCloudScan = settings.Values["CloudScan"] as bool? ?? false;
            bool UseSouXiaoScan = settings.Values["SouXiaoScan"] as bool? ?? false;
            bool UseModelScan = settings.Values["ModelScan"] as bool? ?? false;

            Helper.ScanEngine.SouXiaoEngineScan? SouXiaoEngine = null;
            Helper.ScanEngine.ModelEngineScan? ModelEngine = null;

            if (UseSouXiaoScan)
            {
                SouXiaoEngine = new();
                if (!SouXiaoEngine.Initialize())
                {
                    _dispatcherQueue.TryEnqueue(async () =>
                    {
                        var dialog = new ContentDialog
                        {
                            Title = Localizer.Get().GetLocalizedString("SecurityPage_SouXiao_InitFailed_Title"),
                            Content = Localizer.Get().GetLocalizedString("SecurityPage_InitFailed_Content"),
                            PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                            XamlRoot = this.XamlRoot,
                            RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                            DefaultButton = ContentDialogButton.Primary
                        };
                        await dialog.ShowAsync();
                    });
                    return;
                }
            }

            if (UseModelScan)
            {
                ModelEngine = new Helper.ScanEngine.ModelEngineScan();
                if (!ScanEngine.ModelEngineScan.Initialize())
                {
                    _dispatcherQueue.TryEnqueue(async () =>
                    {
                        var dialog = new ContentDialog
                        {
                            Title = Localizer.Get().GetLocalizedString("SecurityPage_Model_InitFailed_Title"),
                            Content = Localizer.Get().GetLocalizedString("SecurityPage_InitFailed_Content"),
                            PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                            XamlRoot = this.XamlRoot,
                            RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                            DefaultButton = ContentDialogButton.Primary
                        };
                        await dialog.ShowAsync();
                    });
                    return;
                }
            }
            var enginesLog = "Use";
            if (UseLocalScan) enginesLog += DeepScan ? " LocalScan-DeepScan" : " LocalScan";
            if (UseCzkCloudScan) enginesLog += " CzkCloudScan";
            if (UseCloudScan) enginesLog += " CloudScan";
            if (UseSouXiaoScan) enginesLog += " SouXiaoScan";
            if (UseModelScan) enginesLog += " Xdows-Model";
            LogText.AddNewLog(LogText.LogLevel.INFO, "Security - StartScan", enginesLog);

            string? userPath = null;
            if (mode is ScanMode.File or ScanMode.Folder)
            {
                userPath = await PickPathAsync(mode);
                if (string.IsNullOrEmpty(userPath))
                {
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        StatusText.Text = Localizer.Get().GetLocalizedString("SecurityPage_Status_Cancelled");
                        StopRadarAnimation();
                    });
                    return;
                }
            }

            ScanButton.IsEnabled = false;

            _filesScanned = 0; _filesSafe = 0; _threatsFound = 0;
            UpdateScanStats(0, 0, 0);

            for (int i = 0; i < _scanItems!.Count; i++)
                UpdateScanItemStatus(i, Localizer.Get().GetLocalizedString("SecurityPage_Status_Waiting"), false, 0);

            CurrentResults = new ObservableCollection<VirusRow>();
            _dispatcherQueue.TryEnqueue(() =>
            {
                ScanProgress.IsIndeterminate = !showScanProgress;
                VirusList.ItemsSource = CurrentResults;
                ScanProgress.Value = 0;
                ScanProgress.Visibility = Visibility.Visible;
                ProgressPercentText.Text = showScanProgress ? "0%" : string.Empty;
                PathText.Text = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_PathText_Format"), displayName);
                BackToVirusListButton.Visibility = Visibility.Collapsed;
                PauseScanButton.Visibility = Visibility.Visible;
                PauseScanButton.IsEnabled = false;
                ResumeScanButton.Visibility = Visibility.Collapsed;
                StatusText.Text = Localizer.Get().GetLocalizedString("SecurityPage_Status_Processing");
                OnBackList(false);
                StartRadarAnimation();
            });

            ScanId++;

            await Task.Run(async () =>
            {
                try
                {
                    var filesList = EnumerateFiles(mode, userPath, customPaths);
                    bool parallelIndex = scanIndexMode == "Parallel";

                    IEnumerable<string> files = parallelIndex ? EnumerateFilesStreaming(mode, userPath, customPaths) : filesList;
                    int total = parallelIndex ? 0 : filesList.Count;

                    DateTime startTime = DateTime.Now;
                    int finished = 0;
                    int currentItemIndex = mode switch
                    {
                        ScanMode.Quick => 0,
                        ScanMode.Full => 1,
                        ScanMode.File => 2,
                        ScanMode.Folder => 3,
                        ScanMode.More => 0,
                        _ => 0
                    };

                    UpdateScanItemStatus(currentItemIndex, Localizer.Get().GetLocalizedString("SecurityPage_Status_Scanning"), true);
                    _dispatcherQueue.TryEnqueue(() => PauseScanButton.IsEnabled = true);

                    int thisId = ScanId;

                    string tStatusText = Localizer.Get().GetLocalizedString("SecurityPage_Status_Scanning");
                    TimeSpan pausedTime = TimeSpan.Zero;
                    DateTime lastPauseTime = DateTime.MinValue;
                    string czkApiKey = App.GetCzkCloudApiKey();
                    bool ScanInside = settings.Values["ScanInside"] as bool? ?? false;
                    bool ScanInsideNested = settings.Values["ScanInsideNested"] as bool? ?? false;

                    foreach (var file in files)
                    {
                        while (_isPaused && !token.IsCancellationRequested)
                        {
                            if (lastPauseTime == DateTime.MinValue) lastPauseTime = DateTime.Now;
                            await Task.Delay(100, token);
                        }

                        if (lastPauseTime != DateTime.MinValue)
                        {
                            pausedTime += DateTime.Now - lastPauseTime;
                            lastPauseTime = DateTime.MinValue;
                        }

                        if (token.IsCancellationRequested) break;

                        _dispatcherQueue.TryEnqueue(() =>
                        {
                            LogText.AddNewLog(LogText.LogLevel.INFO, "Security - ScanFile", file);
                            try { StatusText.Text = string.Format(tStatusText, file); } catch { }
                        });

                        if (ScanInside && ZipScanner.IsZipFile(file))
                        {
                            await ScanZipFileAsync(file, ScanInsideNested, DeepScan, ExtraData, UseLocalScan, UseCloudScan, UseCzkCloudScan, UseSouXiaoScan, UseModelScan, SouXiaoEngine, ModelEngine, czkApiKey, token);
                            _filesScanned++;
                            finished++;
                            continue;
                        }

                        try
                        {
                            if (TrustManager.IsPathTrusted(file))
                            {
                                LogText.AddNewLog(LogText.LogLevel.INFO, "Security - Find", "Is Trusted");
                                _filesSafe++;
                                continue;
                            }

                            var scanRes = await RunScansOnFileAsync(file, DeepScan, ExtraData, UseLocalScan, UseCloudScan, UseCzkCloudScan, UseSouXiaoScan, UseModelScan, SouXiaoEngine, ModelEngine, czkApiKey, token);
                            Statistics.ScansQuantity += 1;
                            if (!String.IsNullOrEmpty(scanRes.VirusInfo))
                            {
                                LogText.AddNewLog(LogText.LogLevel.INFO, "Security - Find", scanRes.VirusInfo);
                                Statistics.VirusQuantity += 1;
                                _dispatcherQueue.TryEnqueue(() =>
                                {
                                    AddVirusResult(file, scanRes.VirusInfo);
                                    BackToVirusListButton.Visibility = Visibility.Visible;
                                });
                                _threatsFound++;
                                UpdateScanItemStatus(currentItemIndex, Localizer.Get().GetLocalizedString("SecurityPage_Status_FoundThreat"), true, _threatsFound);
                            }
                            else
                            {
                                LogText.AddNewLog(LogText.LogLevel.INFO, "Security - Find", "Is Safe");
                                _filesSafe++;
                            }
                        }
                        catch (Exception ex)
                        {
                            LogText.AddNewLog(LogText.LogLevel.WARN, "Security - ScanFailed", ex.Message);
                        }

                        finished++;
                        _filesScanned = finished;
                        TimeSpan elapsedTime = DateTime.Now - startTime - pausedTime;
                        double scanSpeed = elapsedTime.TotalSeconds > 0 ? finished / elapsedTime.TotalSeconds : 0.0;
                        _dispatcherQueue.TryEnqueue(() => ScanSpeedText.Text = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_ScanSpeed_Format"), scanSpeed));

                        if (showScanProgress)
                        {
                            double percent = total == 0 ? 100 : (double)finished / total * 100;
                            _dispatcherQueue.TryEnqueue(() => { ScanProgress.Value = percent; ProgressPercentText.Text = $"{percent:F0}%"; });
                        }

                        try { UpdateScanStats(_filesScanned, _filesSafe, _threatsFound); } catch { }

                        if (MainWindow.NowPage != "Security" || thisId != ScanId) break;
                        await Task.Delay(1, token);
                    }

                    UpdateScanItemStatus(currentItemIndex, Localizer.Get().GetLocalizedString("SecurityPage_Status_Completed"), false, _threatsFound);

                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        ApplicationDataContainer settingsLocal = ApplicationData.Current.LocalSettings;
                        settingsLocal.Values["LastScanTime"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                        StatusText.Text = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_ScanCompleteFound"), CurrentResults?.Count ?? 0);
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
                        StatusText.Text = Localizer.Get().GetLocalizedString("SecurityPage_ScanCancelled");
                        ScanProgress.Visibility = Visibility.Collapsed;
                        ResumeScanButton.Visibility = Visibility.Collapsed;
                        StopRadarAnimation();
                    });
                }
                catch (Exception ex)
                {
                    _dispatcherQueue.TryEnqueue(() =>
                    {
                        LogText.AddNewLog(LogText.LogLevel.FATAL, "Security - Failed", ex.Message);
                        StatusText.Text = string.Format(Localizer.Get().GetLocalizedString("SecurityPage_ScanFailed_Format"), ex.Message);
                        ScanProgress.Visibility = Visibility.Collapsed;
                        PauseScanButton.Visibility = Visibility.Collapsed;
                        ResumeScanButton.Visibility = Visibility.Collapsed;
                        StopRadarAnimation();
                    });
                }
            });

            ScanButton.IsEnabled = true;
        }

        private void OnBackToVirusListClick(Object sender, RoutedEventArgs e)
        {
            OnBackList(VirusList.Visibility != Visibility.Visible);
        }

        private void OnBackList(Boolean isShow)
        {
            VirusList.Visibility = isShow ? Visibility.Visible : Visibility.Collapsed;
            BackToVirusListButtonText.Text = isShow ? Localizer.Get().GetLocalizedString("SecurityPage_BackToVirusList_Hide") : Localizer.Get().GetLocalizedString("SecurityPage_BackToVirusList_Show");
            BackToVirusListButtonIcon.Glyph = isShow ? "\uED1A" : "\uE890";
        }

        private void OnPauseScanClick(Object sender, RoutedEventArgs e)
        {
            _isPaused = true;
            ScanButton.IsEnabled = true;
            PauseScanButton.Visibility = Visibility.Collapsed;
            ResumeScanButton.Visibility = Visibility.Visible;
            PauseRadarAnimation();
        }

        private void OnResumeScanClick(Object sender, RoutedEventArgs e)
        {
            _isPaused = false;
            ScanButton.IsEnabled = false;
            PauseScanButton.Visibility = Visibility.Visible;
            ResumeScanButton.Visibility = Visibility.Collapsed;
            ResumeRadarAnimation();
        }

        private async void VirusList_DoubleTapped(Object sender, DoubleTappedRoutedEventArgs e)
        {
            if (sender is ListView { SelectedItem: VirusRow row })
            {
                await ShowDetailsDialog(row);
            }
        }

        private async Task ShowDetailsDialog(VirusRow? row)
        {
            Boolean isDetailsPause = false;
            Boolean scanWasResumed = false;
            try
            {
                if (row is null) return;
                isDetailsPause = PauseScanButton.Visibility == Visibility.Visible && PauseScanButton.IsEnabled;
                if (isDetailsPause)
                {
                    OnPauseScanClick(new Object(), new RoutedEventArgs());
                }

                String displayPath = row.FilePath;
                String? zipPath = null;
                String? entryPath = null;
                Boolean isZipEntry = false;

                Int32 zipIndex = displayPath.IndexOf(".zip\\", StringComparison.OrdinalIgnoreCase);
                if (zipIndex > 0)
                {
                    zipPath = displayPath.Substring(0, zipIndex + 4);
                    entryPath = displayPath.Substring(zipIndex + 5);
                    isZipEntry = true;
                }

                String fileSizeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_Unknown");
                String creationTimeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_Unknown");
                String lastWriteTimeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_Unknown");

                if (isZipEntry && zipPath != null && entryPath != null)
                {
                    try
                    {
                        var entryInfo = await ZipScanner.GetEntryInfoAsync(zipPath, entryPath);
                        if (entryInfo.HasValue)
                        {
                            fileSizeText = String.Format("{0:F2} KB", entryInfo.Value.Size / 1024.0);
                            creationTimeText = entryInfo.Value.CreationTime.ToString();
                            lastWriteTimeText = entryInfo.Value.LastWriteTime.ToString();
                        }
                        else
                        {
                            fileSizeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_NotAvailable");
                        }
                    }
                    catch
                    {
                        fileSizeText = Localizer.Get().GetLocalizedString("SecurityPage_Details_NotAvailable");
                    }
                }
                else if (System.IO.File.Exists(displayPath))
                {
                    try
                    {
                        FileInfo fileInfo = new(displayPath);
                        fileSizeText = String.Format("{0:F2} KB", fileInfo.Length / 1024.0);
                        creationTimeText = fileInfo.CreationTime.ToString();
                        lastWriteTimeText = fileInfo.LastWriteTime.ToString();
                    }
                    catch { }
                }

                ContentDialog dialog = new()
                {
                    Title = Localizer.Get().GetLocalizedString("SecurityPage_Details_Title"),
                    Content = new ScrollViewer
                    {
                        Content = new StackPanel
                        {
                            Children =
                            {
                                new TextBlock { Text = Localizer.Get().GetLocalizedString("SecurityPage_Details_FilePath"), Margin = new Thickness(0, 8, 0, 0) },
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
                                                new Run { Text = displayPath },
                                            }
                                        }
                                    }
                                },
                                new TextBlock { Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_Details_VirusName"), row.VirusName), Margin = new Thickness(0, 8, 0, 0) },
                                new TextBlock { Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_Details_FileSize"), fileSizeText), Margin = new Thickness(0, 8, 0, 0) },
                                new TextBlock { Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_Details_CreationTime"), creationTimeText), Margin = new Thickness(0, 8, 0, 0) },
                                new TextBlock { Text = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_Details_LastWriteTime"), lastWriteTimeText), Margin = new Thickness(0, 8, 0, 0) }
                            }
                        },
                        MaxHeight = 400
                    },
                    PrimaryButtonText = isZipEntry ? null : Localizer.Get().GetLocalizedString("SecurityPage_Details_LocateButton"),
                    CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                    XamlRoot = this.XamlRoot,
                    RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    DefaultButton = ContentDialogButton.Close
                };
                if (!isZipEntry && await dialog.ShowAsync() == ContentDialogResult.Primary)
                {
                    try
                    {
                        String filePath = displayPath;
                        String? directoryPath = Path.GetDirectoryName(filePath);
                        String fileName = Path.GetFileName(filePath);

                        System.Diagnostics.ProcessStartInfo psi = new()
                        {
                            FileName = "explorer.exe",
                        };
                        String safeFilePath = filePath.Replace("\"", "\\\"");
                        psi.Arguments = $"/select,\"{safeFilePath}\"";
                        System.Diagnostics.Process.Start(psi);
                    }
                    catch (Exception ex)
                    {
                        ContentDialog dlg = new()
                        {
                            Title = Localizer.Get().GetLocalizedString("SecurityPage_LocateFailed_Title"),
                            Content = String.Format(Localizer.Get().GetLocalizedString("SecurityPage_LocateFailed_Content"), ex.Message),
                            CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                            RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                            XamlRoot = this.XamlRoot,
                            DefaultButton = ContentDialogButton.Close
                        };
                        await dlg.ShowAsync();
                    }
                }
                else if (isZipEntry)
                {
                    await dialog.ShowAsync();
                }
            }
            catch (Exception ex)
            {
                try
                {
                    LogText.AddNewLog(LogText.LogLevel.FATAL, "Security - FilesInfo - GetFailed", ex.Message);
                    ContentDialog failDlg = new()
                    {
                        Title = Localizer.Get().GetLocalizedString("SecurityPage_GetFailed_Text"),
                        Content = ex.Message,
                        CloseButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                        XamlRoot = this.XamlRoot,
                        RequestedTheme = (XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                        DefaultButton = ContentDialogButton.Close
                    };
                    await failDlg.ShowAsync();
                }
                catch { }
            }
            finally
            {
                if (isDetailsPause && !scanWasResumed)
                {
                    try
                    {
                        OnResumeScanClick(new Object(), new RoutedEventArgs());
                        scanWasResumed = true;
                    }
                    catch (Exception resumeEx)
                    {
                        LogText.AddNewLog(LogText.LogLevel.ERROR, "Security - ResumeFailed", resumeEx.Message);
                    }
                }
            }
        }

        private async Task<String?> PickPathAsync(ScanMode mode)
        {
            try
            {
                if (mode == ScanMode.File)
                {
                    PickFileResult file = await (new FileOpenPicker(XamlRoot.ContentIslandEnvironment.AppWindowId).PickSingleFileAsync());
                    if (file is null) { return null; }
                    return file.Path;
                }
                else
                {
                    PickFolderResult folder = await (new FolderPicker(XamlRoot.ContentIslandEnvironment.AppWindowId).PickSingleFolderAsync());
                    if (folder is null) { return null; }
                    return folder.Path;
                }
            }
            catch { return null; }
        }

        private static List<String> EnumerateFiles(ScanMode mode, String? userPath, IReadOnlyList<String>? customPaths) => mode switch
        {
            ScanMode.Quick => [.. GetEnumerateQuickScanFiles()],
            ScanMode.Full => [.. EnumerateFullScanFiles()],
            ScanMode.File => (userPath != null && System.IO.File.Exists(userPath))
                              ? [userPath]
                              : [],
            ScanMode.Folder => (userPath != null && Directory.Exists(userPath))
                              ? [.. SafeEnumerateFolder(userPath)]
                              : [],
            ScanMode.More => customPaths?.SelectMany(p =>
            {
                if (Directory.Exists(p))
                    return SafeEnumerateFolder(p);
                else if (System.IO.File.Exists(p))
                    return [p];
                return [];
            }).ToList() ?? [],
            _ => []
        };

        private static IEnumerable<String> SafeEnumerateFolder(String folder)
        {
            Stack<String> stack = new();
            stack.Push(folder);

            while (stack.Count > 0)
            {
                String dir = stack.Pop();

                IEnumerable<String> entries;
                try { entries = Directory.EnumerateFileSystemEntries(dir); }
                catch { continue; }

                foreach (String entry in entries)
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

        private static IEnumerable<string> GetEnumerateQuickScanFiles()
        {
            String[] criticalPaths =
            [
                 Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                 Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                 Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                 Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                 Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                 Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                 Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"),
                 Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64")
            ];

            HashSet<String> extensions = new(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".sys", ".com", ".scr", ".bat" };

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
                           return [];
                       }
                   })
                   .Distinct(StringComparer.OrdinalIgnoreCase);
        }

        private static IEnumerable<String> EnumerateFullScanFiles()
        {
            HashSet<String> scanned = new(StringComparer.OrdinalIgnoreCase);

            foreach (DriveInfo drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady || drive.DriveType is DriveType.CDRom or DriveType.Network)
                    continue;

                foreach (String file in SafeEnumerateFiles(drive.RootDirectory.FullName, scanned))
                    yield return file;
            }
        }

        private static IEnumerable<String> SafeEnumerateFiles(String root, HashSet<String> scanned)
        {
            Stack<String> stack = new();
            stack.Push(root);

            while (stack.Count > 0)
            {
                String currentDir = stack.Pop();

                if (!scanned.Add(currentDir))
                    continue;

                IEnumerable<String>? entries;
                try
                {
                    entries = Directory.EnumerateFileSystemEntries(currentDir);
                }
                catch
                {
                    continue;
                }

                foreach (String entry in entries)
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
