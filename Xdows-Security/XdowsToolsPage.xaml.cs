using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.System;
using Windows.UI.Core;
using WinRT;

namespace Xdows_Security
{
    public sealed partial class XdowsToolsPage : Page
    {
        private ObservableCollection<ProcessInfo> _processes;
        private List<ProcessInfo> _allProcesses;
        private CancellationTokenSource _repairCancellationTokenSource;
        private ObservableCollection<RiskItem> _riskItems;
        private bool _isScanning;
        private bool _isInitialized;

        private List<string> _commandHistory = new List<string>();
        private int _currentHistoryIndex = -1;

        public XdowsToolsPage()
        {
            this.InitializeComponent();

            // 初始化字段
            _processes = new ObservableCollection<ProcessInfo>();
            _allProcesses = new List<ProcessInfo>();
            _riskItems = new ObservableCollection<RiskItem>();
            _isScanning = false;
            _isInitialized = false;

            ProcessList.ItemsSource = _processes;
            RiskItemsList.ItemsSource = _riskItems;

            // 设置初始文本
            TabTitle.Text = "进程管理";
            RepairTabTitle.Text = "系统修复工具";

            // 刷新进程列表
            //RefreshProcessList();
        }

        private void Page_Loaded(object sender, RoutedEventArgs e)
        {
            _isInitialized = true;

            // 确保UI控件已初始化
            if (ScanStatus != null)
                ScanStatus.Text = "准备就绪";
            if (CurrentScanItem != null)
                CurrentScanItem.Text = "等待开始扫描...";
            if (RepairSummary != null)
                RepairSummary.Text = "准备开始系统扫描...";
            if (ScanProgressBar != null)
                ScanProgressBar.Value = 0;
            if (ScanProgressText != null)
                ScanProgressText.Text = "";
        }

        private void TabView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var tabView = sender as TabView;
            if (tabView != null)
            {
                var selectedTab = tabView.SelectedItem as TabViewItem;
                if (selectedTab != null)
                {
                    switch (selectedTab.Header.ToString())
                    {
                        case "进程管理":
                            TabTitle.Text = "进程管理";
                            break;
                        case "命令提示符":
                            CmdTabTitle.Text = "命令提示符";
                            break;
                        case "系统修复":
                            RepairTabTitle.Text = "系统修复工具";
                            break;
                    }
                }
            }
        }

        #region 系统修复功能

        private async void StartRepairScan_Click(object sender, RoutedEventArgs e)
        {
            if (_isScanning) return;

            if (!_isInitialized)
            {
                var dialog = new ContentDialog
                {
                    Title = "系统未初始化",
                    Content = "系统修复工具正在初始化中，请稍后再试",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                };
                await dialog.ShowAsync();
                return;
            }

            // 检查UI控件是否已初始化
            if (ScanStatus == null || CurrentScanItem == null || RepairSummary == null || ScanProgressBar == null || ScanProgressText == null)
            {
                var dialog = new ContentDialog
                {
                    Title = "系统初始化错误",
                    Content = "系统修复工具UI组件未完全初始化，请刷新页面重试",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                };
                await dialog.ShowAsync();
                return;
            }

            _isScanning = true;
            _repairCancellationTokenSource = new CancellationTokenSource();
            _riskItems.Clear();

            // 更新UI状态
            ScanStatus.Text = "正在扫描...";
            ScanProgressBar.Value = 0;
            ScanProgressText.Text = "0%";
            CurrentScanItem.Text = "开始系统扫描...";
            RepairSummary.Text = "正在扫描系统问题...";

            try
            {
                // 执行完整的系统扫描
                await PerformFullSystemScan(_repairCancellationTokenSource.Token);

                // 扫描完成 - 确保所有问题都显示在扫描结果框中
                ScanStatus.Text = "扫描完成";
                CurrentScanItem.Text = "系统扫描已完成";
                ScanProgressBar.Value = 100;
                ScanProgressText.Text = "100%";

                // 明确显示所有扫描结果
                if (_riskItems.Count == 0)
                {
                    RepairSummary.Text = "扫描完成，未发现系统问题";
                }
                else
                {
                    RepairSummary.Text = $"扫描完成，共发现 {_riskItems.Count} 个问题项，已全部列出在下方列表中";

                    // 确保所有问题项都可见
                    RiskItemsList.UpdateLayout();
                }

                _isScanning = false;
            }
            catch (OperationCanceledException)
            {
                // 扫描被取消
                ScanStatus.Text = "扫描已取消";
                CurrentScanItem.Text = "用户取消了扫描";
                RepairSummary.Text = "扫描已停止";
                _isScanning = false;
            }
            catch (Exception ex)
            {
                // 扫描出错
                ScanStatus.Text = "扫描出错";
                CurrentScanItem.Text = $"扫描过程中发生错误: {ex.Message}";
                RepairSummary.Text = "扫描过程中发生错误";
                _isScanning = false;
            }
        }

        private async Task PerformFullSystemScan(CancellationToken cancellationToken)
        {
            // 扫描桌面图标显示相关注册表
            await ScanDesktopRegistry(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();

            // 扫描命令提示符相关注册表
            await ScanCommandPromptRegistry(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();

            // 扫描鼠标设置相关注册表
            await ScanMouseRegistry(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();

            // 扫描任务管理器相关注册表
            await ScanTaskManagerRegistry(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();

            // 扫描注册表编辑器相关注册表
            await ScanRegeditRegistry(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();

            // 确保进度达到100%并添加延迟让用户看到完成状态
            await UpdateProgress(100);
            await Task.Delay(1000, cancellationToken);
        }

        private void StopRepairScan_Click(object sender, RoutedEventArgs e)
        {
            if (_repairCancellationTokenSource != null)
            {
                _repairCancellationTokenSource.Cancel();
                _repairCancellationTokenSource.Dispose();
                _repairCancellationTokenSource = null;
            }

            if (ScanStatus != null)
                ScanStatus.Text = "扫描停止";
            if (CurrentScanItem != null)
                CurrentScanItem.Text = "用户取消了扫描";
            if (RepairSummary != null)
                RepairSummary.Text = "扫描已停止";
            _isScanning = false;
        }

        private async Task AddRiskItem(string name, string description, string location, string riskLevel, string riskIcon, string riskColor)
        {
            if (Dispatcher != null)
            {
                await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                {
                    _riskItems.Add(new RiskItem
                    {
                        Name = name,
                        Description = description,
                        Location = location,
                        RiskLevel = riskLevel,
                        RiskIcon = riskIcon,
                        RiskColor = riskColor
                    });
                });
            }
        }

        private async Task ScanDesktopRegistry(CancellationToken cancellationToken)
        {
            await UpdateScanStatus("正在扫描桌面图标显示相关注册表...");
            await UpdateProgress(10);
            await Task.Delay(800, cancellationToken);

            try
            {
                // 检查桌面图标显示
                await UpdateScanStatus("检查桌面图标显示设置...");
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"))
                {
                    if (key != null)
                    {
                        var hideIcons = key.GetValue("HideIcons");
                        if (hideIcons?.ToString() == "1")
                        {
                            await AddRiskItem("桌面图标被隐藏", "桌面图标被设置为隐藏状态", @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "高危", "\uE7BA", "#FF6B35");
                        }
                    }
                    else
                    {
                        await AddRiskItem("注册表访问失败", "无法访问桌面图标设置注册表项", @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "中危", "\uE783", "#FF9800");
                    }
                }

                await Task.Delay(500, cancellationToken);

                // 检查任务栏显示
                await UpdateScanStatus("检查任务栏显示设置...");
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3"))
                {
                    if (key == null)
                    {
                        await AddRiskItem("任务栏显示异常", "任务栏注册表项可能被损坏", @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3", "高危", "\uE7BA", "#FF6B35");
                    }
                }

                await Task.Delay(500, cancellationToken);
                await UpdateProgress(20);
            }
            catch (Exception ex)
            {
                await AddRiskItem("注册表扫描失败", $"无法扫描桌面相关注册表: {ex.Message}", "注册表", "高危", "\uE783", "#D32F2F");
            }
        }

        private async Task ScanCommandPromptRegistry(CancellationToken cancellationToken)
        {
            await UpdateScanStatus("正在扫描命令提示符相关注册表...");
            await UpdateProgress(30);
            await Task.Delay(800, cancellationToken);

            try
            {
                // 检查命令提示符是否被禁用
                await UpdateScanStatus("检查命令提示符状态...");

                bool commandPromptDisabled = false;
                string disabledLocation = "";

                // 检查当前用户策略
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Policies\Microsoft\Windows\System"))
                {
                    if (key != null)
                    {
                        var disableCMD = key.GetValue("DisableCMD");
                        if (disableCMD?.ToString() == "1")
                        {
                            commandPromptDisabled = true;
                            disabledLocation = @"HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System";
                        }
                    }
                }

                // 检查本地机器策略
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\System"))
                {
                    if (key != null)
                    {
                        var disableCMD = key.GetValue("DisableCMD");
                        if (disableCMD?.ToString() == "1")
                        {
                            commandPromptDisabled = true;
                            disabledLocation = @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System";
                        }
                    }
                }

                // 检查另一个可能的CMD禁用位置
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"))
                {
                    if (key != null)
                    {
                        var disableCMD = key.GetValue("DisableCMD");
                        if (disableCMD?.ToString() == "1")
                        {
                            commandPromptDisabled = true;
                            disabledLocation = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
                        }
                    }
                }

                if (commandPromptDisabled)
                {
                    await AddRiskItem("命令提示符被禁用", "命令提示符已被系统策略禁用", disabledLocation, "高危", "\uE783", "#D32F2F");
                }

                await Task.Delay(500, cancellationToken);
                await UpdateProgress(40);
            }
            catch (Exception ex)
            {
                await AddRiskItem("注册表扫描失败", $"无法扫描命令提示符相关注册表: {ex.Message}", "注册表", "高危", "\uE783", "#D32F2F");
            }
        }

        private async Task ScanMouseRegistry(CancellationToken cancellationToken)
        {
            await UpdateScanStatus("正在扫描鼠标设置相关注册表...");
            await UpdateProgress(50);
            await Task.Delay(800, cancellationToken);

            try
            {
                // 检查鼠标左右键
                await UpdateScanStatus("检查鼠标左右键设置...");
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Control Panel\Mouse"))
                {
                    if (key != null)
                    {
                        var swapMouseButtons = key.GetValue("SwapMouseButtons");
                        if (swapMouseButtons?.ToString() == "1")
                        {
                            await AddRiskItem("鼠标左右键颠倒", "鼠标左右键功能可能被颠倒", @"HKEY_CURRENT_USER\Control Panel\Mouse", "中危", "\uE795", "#FFA726");
                        }
                    }
                    else
                    {
                        await AddRiskItem("注册表访问失败", "无法访问鼠标设置注册表项", @"HKEY_CURRENT_USER\Control Panel\Mouse", "中危", "\uE783", "#FF9800");
                    }
                }

                await Task.Delay(500, cancellationToken);
                await UpdateProgress(60);
            }
            catch (Exception ex)
            {
                await AddRiskItem("注册表扫描失败", $"无法扫描鼠标相关注册表: {ex.Message}", "注册表", "高危", "\uE783", "#D32F2F");
            }
        }

        private async Task ScanTaskManagerRegistry(CancellationToken cancellationToken)
        {
            await UpdateScanStatus("正在扫描任务管理器相关注册表...");
            await UpdateProgress(70);
            await Task.Delay(800, cancellationToken);

            try
            {
                // 检查任务管理器是否被禁用
                await UpdateScanStatus("检查任务管理器状态...");

                bool taskManagerDisabled = false;
                string disabledLocation = "";

                // 检查当前用户策略
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System"))
                {
                    if (key != null)
                    {
                        var disableTaskMgr = key.GetValue("DisableTaskMgr");
                        if (disableTaskMgr?.ToString() == "1")
                        {
                            taskManagerDisabled = true;
                            disabledLocation = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System";
                        }
                    }
                }

                // 检查本地机器策略
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
                {
                    if (key != null)
                    {
                        var disableTaskMgr = key.GetValue("DisableTaskMgr");
                        if (disableTaskMgr?.ToString() == "1")
                        {
                            taskManagerDisabled = true;
                            disabledLocation = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
                        }
                    }
                }

                if (taskManagerDisabled)
                {
                    await AddRiskItem("任务管理器被禁用", "任务管理器已被系统策略禁用", disabledLocation, "高危", "\uE783", "#D32F2F");
                }

                await Task.Delay(500, cancellationToken);
                await UpdateProgress(80);
            }
            catch (Exception ex)
            {
                await AddRiskItem("注册表扫描失败", $"无法扫描任务管理器相关注册表: {ex.Message}", "注册表", "高危", "\uE783", "#D32F2F");
            }
        }

        private async Task ScanRegeditRegistry(CancellationToken cancellationToken)
        {
            await UpdateScanStatus("正在扫描注册表编辑器相关注册表...");
            await UpdateProgress(90);
            await Task.Delay(800, cancellationToken);

            try
            {
                // 检查注册表编辑器是否被禁用
                await UpdateScanStatus("检查注册表编辑器状态...");

                bool registryEditorDisabled = false;
                string disabledLocation = "";

                // 检查当前用户策略
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System"))
                {
                    if (key != null)
                    {
                        var disableRegistryTools = key.GetValue("DisableRegistryTools");
                        if (disableRegistryTools?.ToString() == "1")
                        {
                            registryEditorDisabled = true;
                            disabledLocation = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System";
                        }
                    }
                }

                // 检查本地机器策略
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"))
                {
                    if (key != null)
                    {
                        var disableRegistryTools = key.GetValue("DisableRegistryTools");
                        if (disableRegistryTools?.ToString() == "1")
                        {
                            registryEditorDisabled = true;
                            disabledLocation = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
                        }
                    }
                }

                if (registryEditorDisabled)
                {
                    await AddRiskItem("注册表编辑器被禁用", "注册表编辑器已被系统策略禁用", disabledLocation, "高危", "\uE783", "#D32F2F");
                }

                await Task.Delay(500, cancellationToken);
                await UpdateProgress(95);
            }
            catch (Exception ex)
            {
                await AddRiskItem("注册表扫描失败", $"无法扫描注册表编辑器相关注册表: {ex.Message}", "注册表", "高危", "\uE783", "#D32F2F");
            }
        }

        private async Task UpdateProgress(int progress)
        {
            if (Dispatcher != null)
            {
                await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                {
                    if (ScanProgressBar != null)
                        ScanProgressBar.Value = progress;
                    if (ScanProgressText != null)
                        ScanProgressText.Text = $"{progress}%";
                });
            }
        }

        private async Task UpdateScanStatus(string status)
        {
            if (Dispatcher != null)
            {
                await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                {
                    if (CurrentScanItem != null)
                        CurrentScanItem.Text = status;
                });
            }
        }

        private void SelectAll_Click(object sender, RoutedEventArgs e)
        {
            foreach (var item in _riskItems)
            {
                item.IsSelected = true;
            }
        }

        private async void RepairSelected_Click(object sender, RoutedEventArgs e)
        {
            var selectedItems = _riskItems.Where(item => item.IsSelected).ToList();
            if (selectedItems.Count == 0)
            {
                var dialog = new ContentDialog
                {
                    Title = "未选择项目",
                    Content = "请先选择要修复的问题",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                };
                await dialog.ShowAsync();
                return;
            }

            await RepairItems(selectedItems);
        }

        private async void RepairAll_Click(object sender, RoutedEventArgs e)
        {
            if (_riskItems.Count == 0)
            {
                var dialog = new ContentDialog
                {
                    Title = "无可修复项目",
                    Content = "当前没有需要修复的问题",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                };
                await dialog.ShowAsync();
                return;
            }

            await RepairItems(_riskItems.ToList());
        }

        private async Task RepairItems(List<RiskItem> items)
        {
            var progressDialog = new ContentDialog
            {
                Title = "正在修复问题",
                Content = "正在修复选中的系统问题，请稍候...",
                CloseButtonText = "取消",
                XamlRoot = XamlRoot
            };

            var progress = new ProgressBar
            {
                IsIndeterminate = true,
                Margin = new Thickness(0, 12, 0, 0)
            };

            var panel = new StackPanel();
            panel.Children.Add(progress);
            progressDialog.Content = panel;

            var tcs = new TaskCompletionSource<bool>();
            progressDialog.Closed += (s, args) => tcs.SetResult(true);
            progressDialog.ShowAsync();

            int successCount = 0;
            int failureCount = 0;

            foreach (var item in items)
            {
                try
                {
                    bool repairResult = await RepairSingleItem(item);
                    if (repairResult)
                    {
                        successCount++;
                        item.IsRepaired = true;
                    }
                    else
                    {
                        failureCount++;
                    }
                }
                catch (Exception ex)
                {
                    failureCount++;
                }
            }

            progressDialog.Hide();

            var resultDialog = new ContentDialog
            {
                Title = "修复完成",
                Content = $"修复完成：成功 {successCount} 项，失败 {failureCount} 项",
                CloseButtonText = "确定",
                XamlRoot = XamlRoot
            };
            await resultDialog.ShowAsync();
        }

        private async Task<bool> RepairSingleItem(RiskItem item)
        {
            try
            {
                switch (item.Name)
                {
                    case "桌面图标被隐藏":
                        using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"))
                        {
                            key.SetValue("HideIcons", 0, RegistryValueKind.DWord);
                        }
                        return true;

                    case "命令提示符被禁用":
                        // 删除禁用CMD的注册表项
                        Registry.CurrentUser.DeleteSubKey(@"Software\Policies\Microsoft\Windows\System", false);
                        Registry.LocalMachine.DeleteSubKey(@"SOFTWARE\Policies\Microsoft\Windows\System", false);
                        Registry.LocalMachine.DeleteSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", false);
                        return true;

                    case "鼠标左右键颠倒":
                        using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Control Panel\Mouse"))
                        {
                            key.SetValue("SwapMouseButtons", 0, RegistryValueKind.DWord);
                        }
                        return true;

                    case "任务管理器被禁用":
                        // 删除禁用任务管理器的注册表项
                        Registry.CurrentUser.DeleteSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", false);
                        Registry.LocalMachine.DeleteSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", false);
                        return true;

                    case "注册表编辑器被禁用":
                        // 删除禁用注册表编辑器的注册表项
                        Registry.CurrentUser.DeleteSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System", false);
                        Registry.LocalMachine.DeleteSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", false);
                        return true;

                    default:
                        return false;
                }
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region 进程管理功能

        private void Refresh_Click(object sender, RoutedEventArgs e)
        {
            RefreshProcessList();
        }

        private void Kill_Click(object sender, RoutedEventArgs e)
        {
            var selectedProcess = ProcessList.SelectedItem as ProcessInfo;
            if (selectedProcess != null)
            {
                try
                {
                    var process = Process.GetProcessById(selectedProcess.Id);
                    process.Kill();
                    RefreshProcessList();
                }
                catch (Exception ex)
                {
                    // 处理异常
                }
            }
        }

        private void SortCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var selectedItem = SortCombo.SelectedItem as ComboBoxItem;
            if (selectedItem != null)
            {
                string sortTag = selectedItem.Tag.ToString();
                SortProcesses(sortTag);
            }
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string searchText = SearchBox.Text.ToLower();
            FilterProcesses(searchText);
        }

        private void RefreshProcessList()
        {
            _allProcesses.Clear();
            _processes.Clear();

            var processes = Process.GetProcesses();
            foreach (var process in processes)
            {
                try
                {
                    var processInfo = new ProcessInfo
                    {
                        Name = process.ProcessName,
                        Id = process.Id,
                        Memory = (process.WorkingSet64 / 1024 / 1024).ToString("F2") + " MB"
                    };
                    _allProcesses.Add(processInfo);
                    _processes.Add(processInfo);
                }
                catch
                {
                    // 忽略无法访问的进程
                }
            }
        }

        private void SortProcesses(string sortBy)
        {
            var sortedList = new List<ProcessInfo>(_processes);

            switch (sortBy)
            {
                case "Name":
                    sortedList = sortedList.OrderBy(p => p.Name).ToList();
                    break;
                case "Id":
                    sortedList = sortedList.OrderBy(p => p.Id).ToList();
                    break;
                case "Memory":
                    sortedList = sortedList.OrderBy(p => double.Parse(p.Memory.Replace(" MB", ""))).ToList();
                    break;
            }

            _processes.Clear();
            foreach (var item in sortedList)
            {
                _processes.Add(item);
            }
        }

        private void FilterProcesses(string searchText)
        {
            _processes.Clear();

            var filteredList = _allProcesses.Where(p => p.Name.ToLower().Contains(searchText)).ToList();

            foreach (var item in filteredList)
            {
                _processes.Add(item);
            }
        }

        #endregion

        #region 命令提示符功能

        private async void ExecuteButton_Click(object sender, RoutedEventArgs e)
        {
            string command = CmdInput.Text.Trim();
            if (string.IsNullOrEmpty(command)) return;

            // 添加到历史记录
            _commandHistory.Add(command);
            _currentHistoryIndex = _commandHistory.Count;

            // 显示执行的命令
            CmdOutput.Text += Environment.NewLine + "> " + command;

            try
            {
                // 创建进程执行命令
                var processInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c " + command,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                var process = Process.Start(processInfo);
                string output = await process.StandardOutput.ReadToEndAsync();
                string error = await process.StandardError.ReadToEndAsync();
                process.WaitForExit();

                // 显示输出
                if (!string.IsNullOrEmpty(output))
                {
                    CmdOutput.Text += Environment.NewLine + output;
                }
                if (!string.IsNullOrEmpty(error))
                {
                    CmdOutput.Text += Environment.NewLine + "错误: " + error;
                }
            }
            catch (Exception ex)
            {
                CmdOutput.Text += Environment.NewLine + "执行错误: " + ex.Message;
            }

            // 清空输入框
            CmdInput.Text = "";

            // 滚动到底部
            CmdOutput.SelectionStart = CmdOutput.Text.Length;
            CmdOutput.SelectionLength = 0;
        }

        private void CmdInput_KeyDown(object sender, KeyRoutedEventArgs e)
        {
            if (e.Key == Windows.System.VirtualKey.Enter)
            {
                ExecuteButton_Click(sender, e);
            }
            else if (e.Key == Windows.System.VirtualKey.Up)
            {
                // 上箭头键 - 显示上一个命令
                if (_currentHistoryIndex > 0)
                {
                    _currentHistoryIndex--;
                    CmdInput.Text = _commandHistory[_currentHistoryIndex];
                }
            }
            else if (e.Key == Windows.System.VirtualKey.Down)
            {
                // 下箭头键 - 显示下一个命令
                if (_currentHistoryIndex < _commandHistory.Count - 1)
                {
                    _currentHistoryIndex++;
                    CmdInput.Text = _commandHistory[_currentHistoryIndex];
                }
                else if (_currentHistoryIndex == _commandHistory.Count - 1)
                {
                    _currentHistoryIndex = _commandHistory.Count;
                    CmdInput.Text = "";
                }
            }
        }

        private void ClearOutput_Click(object sender, RoutedEventArgs e)
        {
            CmdOutput.Text = "[Ver 1.0.0] XIGUASystem 命令提示符 cmd";
        }

        private async void CopyOutput_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(CmdOutput.Text))
            {
                var dataPackage = new Windows.ApplicationModel.DataTransfer.DataPackage();
                dataPackage.SetText(CmdOutput.Text);
                Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(dataPackage);

                var dialog = new ContentDialog
                {
                    Title = "复制成功",
                    Content = "命令输出已复制到剪贴板",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                };
                await dialog.ShowAsync();
            }
        }

        #endregion
    }

    public class ProcessInfo
    {
        public string Name { get; set; }
        public int Id { get; set; }
        public string Memory { get; set; }
    }

    public class RiskItem
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string Location { get; set; }
        public string RiskLevel { get; set; }
        public string RiskIcon { get; set; }
        public string RiskColor { get; set; }
        public bool IsSelected { get; set; }
        public bool IsRepaired { get; set; }
    }
}