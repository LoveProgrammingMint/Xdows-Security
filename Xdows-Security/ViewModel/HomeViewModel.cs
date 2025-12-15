using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.WindowsAPICodePack.Dialogs;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;
using WinUI3Localizer;
using Xdows_Security.Infrastructure;
using Xdows_Security.Model;


namespace Xdows_Security.ViewModel
{
    public sealed partial class HomeViewModel : ObservableObject
    {
        #region === Models ===
        private readonly SystemInfoModel _sys = new();
        private readonly ProtectionModel _prot = new();
        private readonly StatisticsModel _stat = new();
        private readonly LogModel _log = new();
        #endregion

        #region === Timers ===
        private readonly WeakEventTimer _sysTimer = new(TimeSpan.FromSeconds(30));
        private readonly WeakEventTimer _protTimer = new(TimeSpan.FromSeconds(5));
        #endregion

        public HomeViewModel()
        {
            OsName = OsVersion = MemoryUsage = ProtectionStatus
                   = LastScanTime = ThreatCount = TotalScans = TotalThreats
                   = HomePageText = HomePageIcon = PomesLine = string.Empty;
            LogRaw = LogText.Text;
            SelectedLogFilters = [];

            InitTimers();
            RefreshPomes();
        }

        #region === UI 属性 ===
        [ObservableProperty] public partial string OsName { get; set; }
        [ObservableProperty] public partial string OsVersion { get; set; }
        [ObservableProperty] public partial string MemoryUsage { get; set; }
        [ObservableProperty] public partial string ProtectionStatus { get; set; }
        [ObservableProperty] public partial SolidColorBrush ProtectionColor { get; set; } = new();
        [ObservableProperty] public partial string LastScanTime { get; set; }
        [ObservableProperty] public partial string ThreatCount { get; set; }
        [ObservableProperty] public partial string TotalScans { get; set; }
        [ObservableProperty] public partial string TotalThreats { get; set; }
        [ObservableProperty] public partial string HomePageText { get; set; }
        [ObservableProperty] public partial string HomePageIcon { get; set; }
        [ObservableProperty] public partial string PomesLine { get; set; }

        /* 原始日志全文 → 通知属性 */
        [ObservableProperty] public partial string LogRaw { get; set; }
        partial void OnLogRawChanged(string value)
        {
            _log.Reload(value, SelectedLogFilters);
        }

        public string[] SelectedLogFilters { get; set; }
        #endregion

        #region === 只读集合 ===
        public ObservableCollection<string> LogLines => _log.Lines;
        #endregion

        #region === 命令 ===
        [RelayCommand]
        private void RefreshPomes()
        {
            var all = Localizer.Get().GetLocalizedString("HomePage_Pomes")
                               .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
            PomesLine = all.OrderBy(_ => Guid.NewGuid()).FirstOrDefault() ?? "";
        }

        [RelayCommand]
        private void CopySysInfo()
        {
            var pkg = new DataPackage();
            pkg.SetText($"OSName: {OsName}\nOSVersion: {OsVersion}\nMemoryUsage: {MemoryUsage}");
            Clipboard.SetContent(pkg);
        }

        [RelayCommand] private void RefreshSysInfo() => LoadData();
        [RelayCommand] private void RefreshStatistics() => LoadStatistics();
        [RelayCommand] private void ClearLog() => _log.Clear();

        [RelayCommand]
        private async Task ExportLogAsync()
        {
            var dlg = new CommonSaveFileDialog
            {
                Title = Localizer.Get().GetLocalizedString("HomePage_ExportLog_SaveDialog_Title"),
                DefaultFileName = $"XdowsSecurity_Log_{DateTime.Now:yyyyMMdd_HHmmss}.log",
                DefaultExtension = "log",
                OverwritePrompt = true,
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
            };
            dlg.Filters.Add(new CommonFileDialogFilter(
                Localizer.Get().GetLocalizedString("HomePage_ExportLog_Filter_Name"), "*.log"));
            if (dlg.ShowDialog() == CommonFileDialogResult.Ok)
                try { _log.Export(dlg.FileName, LogRaw); }
                catch (Exception ex) { Log(3, "ExportLog", ex.Message); }
        }

        [RelayCommand]
        private void LogLevelFilter(string[]? selected)
        {
            SelectedLogFilters = selected ?? Array.Empty<string>();
            _log.Reload(LogRaw, SelectedLogFilters);
        }
        #endregion

        #region === 加载入口（由 View Loaded 调用）===
        public async Task LoadOnUiThread()
        {
            try
            {
                await Task.Delay(1); // 让 Loading 画出来
                LoadData();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"LoadOnUiThread 异常：{ex}");
            }
        }
        #endregion

        #region === 内部逻辑 ===
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
                OsName = _sys.OSName;
                OsVersion = _sys.OSVersion;
            }
            catch (Exception ex)
            {
                OsName = OsVersion = Localizer.Get().GetLocalizedString("HomePage_GetFailed.Text");
                Log(3, "LoadSystemInfo", ex.Message);
            }
            UpdateMemory();
            LoadProtection();
            LoadStatistics();
            UpdateData();
        }

        private void UpdateMemory()
        {
            var (ok, _, disp) = _sys.GetMemory();
            MemoryUsage = ok ? disp : Localizer.Get().GetLocalizedString("HomePage_GetFailed.Text");
        }
        private void LoadProtection()
        {
            var st = Localizer.Get().GetLocalizedString("AllPage_Status").Split(',');
            var ok = _prot.IsProtected;
            ProtectionStatus = ok ? st[0] : st[1];
            ProtectionColor = ok
            ? new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(255, 78, 201, 176))   // 绿 78, 201, 176
            : new SolidColorBrush(Microsoft.UI.ColorHelper.FromArgb(255, 241, 82, 98));  // 红 241, 82, 98
            LastScanTime = _prot.LastScanTime ?? "—";
            ThreatCount = _prot.ThreatCount.ToString();
        }

        private void LoadStatistics()
        {
            TotalScans = _stat.ScansQuantity.ToString();
            TotalThreats = _stat.VirusQuantity.ToString();
        }

        private void UpdateData()
        {
            var ok = _prot.IsProtected;
            HomePageText = Localizer.Get().GetLocalizedString(ok ? "HomePage_TextBlock_Open"
                                                                 : "HomePage_TextBlock_Close");
            HomePageIcon = ok ? "\uE73E" : "\uE711";
        }

        private void Log(int level, string module, string msg) =>
            _log.Push($"[{level}] {DateTime.Now:HH:mm:ss} [{module}] {msg}");
        #endregion
    }
}