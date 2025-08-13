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
            RefreshProcessList();
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
            if (sender is TabView tabView && tabView.SelectedIndex >= 0)
            {
                var selectedTab = tabView.TabItems[tabView.SelectedIndex];
                if (selectedTab is TabViewItem tabItem)
                {
                    switch (tabItem.Header.ToString())
                    {
                        case "进程管理":
                            TabTitle.Text = "进程管理";
                            break;
                        case "命令行":
                            TabTitle.Text = "命令行";
                            break;
                        case "系统修复":
                            TabTitle.Text = "系统修复";
                            break;
                    }
                }
            }
        }

        #region 进程管理功能

        private void RefreshProcessList()
        {
            try
            {
                _allProcesses.Clear();
                _processes.Clear();

                var currentProcess = Process.GetCurrentProcess();
                var processes = Process.GetProcesses()
                    .Where(p => p.Id != currentProcess.Id)
                    .OrderBy(p => p.ProcessName)
                    .ToList();

                foreach (var process in processes)
                {
                    try
                    {
                        var processInfo = new ProcessInfo(process);
                        _allProcesses.Add(processInfo);
                        _processes.Add(processInfo);
                    }
                    catch
                    {
                        // 忽略无法访问的进程
                    }
                }
            }
            catch (Exception ex)
            {
                var dialog = new ContentDialog
                {
                    Title = "错误",
                    Content = $"无法获取进程列表: {ex.Message}",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                };
                _ = dialog.ShowAsync();
            }
        }

        private void Refresh_Click(object sender, RoutedEventArgs e)
        {
            RefreshProcessList();
        }

        private void SortCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (SortCombo.SelectedItem is ComboBoxItem selectedItem && _allProcesses.Count > 0)
            {
                var sortBy = selectedItem.Tag.ToString();
                var sortedProcesses = sortBy switch
                {
                    "Name" => _allProcesses.OrderBy(p => p.Name).ToList(),
                    "Id" => _allProcesses.OrderBy(p => p.Id).ToList(),
                    "Memory" => _allProcesses.OrderByDescending(p => p.MemoryBytes).ToList(),
                    _ => _allProcesses.ToList()
                };

                _processes.Clear();
                foreach (var process in sortedProcesses)
                {
                    _processes.Add(process);
                }
            }
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            var searchText = SearchBox.Text.ToLower();
            if (string.IsNullOrWhiteSpace(searchText))
            {
                _processes.Clear();
                foreach (var process in _allProcesses)
                {
                    _processes.Add(process);
                }
            }
            else
            {
                var filteredProcesses = _allProcesses
                    .Where(p => p.Name.ToLower().Contains(searchText) || p.Id.ToString().Contains(searchText))
                    .ToList();

                _processes.Clear();
                foreach (var process in filteredProcesses)
                {
                    _processes.Add(process);
                }
            }
        }

        private async void Kill_Click(object sender, RoutedEventArgs e)
        {
            if (ProcessList.SelectedItem is ProcessInfo selectedProcess)
            {
                var confirmDialog = new ContentDialog
                {
                    Title = "确认终止",
                    Content = $"确定要终止进程 {selectedProcess.Name} (PID: {selectedProcess.Id}) 吗？",
                    PrimaryButtonText = "终止",
                    CloseButtonText = "取消",
                    XamlRoot = XamlRoot,
                    PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                };

                if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary)
                {
                    try
                    {
                        var process = Process.GetProcessById(selectedProcess.Id);
                        process.Kill();
                        RefreshProcessList();
                    }
                    catch (Exception ex)
                    {
                        var errorDialog = new ContentDialog
                        {
                            Title = "终止失败",
                            Content = $"无法终止进程: {ex.Message}",
                            CloseButtonText = "确定",
                            XamlRoot = XamlRoot
                        };
                        await errorDialog.ShowAsync();
                    }
                }
            }
            else
            {
                var dialog = new ContentDialog
                {
                    Title = "提示",
                    Content = "请选择要终止的进程",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                };
                await dialog.ShowAsync();
            }
        }

        #endregion

        #region 命令行功能

        private async void ExecuteButton_Click(object sender, RoutedEventArgs e)
        {
            await ExecuteCommand();
        }

        private async void CmdInput_KeyDown(object sender, KeyRoutedEventArgs e)
        {
            if (e.Key == Windows.System.VirtualKey.Enter)
            {
                e.Handled = true;
                await ExecuteCommand();
            }
            else if (e.Key == Windows.System.VirtualKey.Up)
            {
                e.Handled = true;
                NavigateHistory(-1);
            }
            else if (e.Key == Windows.System.VirtualKey.Down)
            {
                e.Handled = true;
                NavigateHistory(1);
            }
        }

        private async Task ExecuteCommand()
        {
            var command = CmdInput.Text.Trim();
            if (string.IsNullOrWhiteSpace(command)) return;

            // 添加到历史记录
            if (!_commandHistory.Contains(command))
            {
                _commandHistory.Add(command);
            }
            _currentHistoryIndex = _commandHistory.Count;

            // 显示命令
            CmdOutput.Text += $"\r> {command}\r\n";
            CmdInput.Text = "";

            try
            {
                var processInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = new Process { StartInfo = processInfo })
                {
                    process.Start();

                    // 异步读取输出
                    var outputTask = process.StandardOutput.ReadToEndAsync();
                    var errorTask = process.StandardError.ReadToEndAsync();

                    await Task.WhenAll(outputTask, errorTask);

                    var output = await outputTask;
                    var error = await errorTask;

                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        CmdOutput.Text += output;
                    }

                    if (!string.IsNullOrWhiteSpace(error))
                    {
                        CmdOutput.Text += $"错误: {error}";
                    }

                    await process.WaitForExitAsync();
                }
            }
            catch (Exception ex)
            {
                CmdOutput.Text += $"执行失败: {ex.Message}\r\n";
            }

            // 滚动到底部
            CmdOutput.Select(CmdOutput.Text.Length, 0);
        }

        private void NavigateHistory(int direction)
        {
            if (_commandHistory.Count == 0) return;

            _currentHistoryIndex += direction;
            _currentHistoryIndex = Math.Max(0, Math.Min(_commandHistory.Count - 1, _currentHistoryIndex));

            CmdInput.Text = _commandHistory[_currentHistoryIndex];
            CmdInput.SelectionStart = CmdInput.Text.Length;
        }

        private void ClearOutput_Click(object sender, RoutedEventArgs e)
        {
            CmdOutput.Text = "命令提示符启动成功，请输入相关命令。";
        }

        private async void CopyOutput_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrWhiteSpace(CmdOutput.Text))
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
                // 直接执行扫描任务，不使用Task.Run包装
                // 扫描桌面图标显示相关注册表
                await ScanDesktopRegistry(_repairCancellationTokenSource.Token);

                // 扫描鼠标设置相关注册表
                await ScanMouseRegistry(_repairCancellationTokenSource.Token);

                // 扫描任务管理器相关注册表
                await ScanTaskManagerRegistry(_repairCancellationTokenSource.Token);

                // 扫描注册表编辑器相关注册表
                await ScanRegeditRegistry(_repairCancellationTokenSource.Token);

                // 扫描完成
                ScanStatus.Text = "扫描完成";
                CurrentScanItem.Text = "系统扫描已完成";
                ScanProgressBar.Value = 100;
                ScanProgressText.Text = "100%";
                RepairSummary.Text = _riskItems.Count == 0
                    ? "未发现系统问题"
                    : $"发现 {_riskItems.Count} 个问题需要修复";
                _isScanning = false;
            }
            catch (OperationCanceledException)
            {
                // 扫描被取消
                ScanStatus.Text = "扫描已取消";
                CurrentScanItem.Text = "用户取消了扫描";
                _isScanning = false;
            }
            catch (Exception ex)
            {
                // 扫描出错
                ScanStatus.Text = "扫描出错";
                CurrentScanItem.Text = $"扫描过程中发生错误: {ex.Message}";
                _isScanning = false;
            }
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
            }
            catch (Exception ex)
            {
                await AddRiskItem("注册表扫描失败", $"无法扫描桌面相关注册表: {ex.Message}", "注册表", "高危", "\uE783", "#D32F2F");
            }
        }

        private async Task ScanMouseRegistry(CancellationToken cancellationToken)
        {
            await UpdateScanStatus("正在扫描鼠标设置相关注册表...");
            await UpdateProgress(30);
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
            }
            catch (Exception ex)
            {
                await AddRiskItem("注册表扫描失败", $"无法扫描鼠标相关注册表: {ex.Message}", "注册表", "高危", "\uE783", "#D32F2F");
            }
        }

        private async Task ScanTaskManagerRegistry(CancellationToken cancellationToken)
        {
            await UpdateScanStatus("正在扫描任务管理器相关注册表...");
            await UpdateProgress(60);
            await Task.Delay(800, cancellationToken);

            try
            {
                // 检查任务管理器是否被禁用
                await UpdateScanStatus("检查任务管理器状态...");

                bool taskManagerDisabled = false;

                // 检查当前用户策略
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System"))
                {
                    if (key != null)
                    {
                        var disableTaskMgr = key.GetValue("DisableTaskMgr");
                        if (disableTaskMgr?.ToString() == "1")
                        {
                            taskManagerDisabled = true;
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
                        }
                    }
                }

                if (taskManagerDisabled)
                {
                    await AddRiskItem("任务管理器被禁用", "任务管理器已被系统策略禁用", @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System", "高危", "\uE783", "#D32F2F");
                }

                await Task.Delay(500, cancellationToken);
            }
            catch (Exception ex)
            {
                await AddRiskItem("注册表扫描失败", $"无法扫描任务管理器相关注册表: {ex.Message}", "注册表", "高危", "\uE783", "#D32F2F");
            }
        }

        private async Task ScanRegeditRegistry(CancellationToken cancellationToken)
        {
            await UpdateScanStatus("正在扫描注册表编辑器相关注册表...");
            await UpdateProgress(85);
            await Task.Delay(800, cancellationToken);

            try
            {
                // 检查注册表编辑器是否被禁用
                await UpdateScanStatus("检查注册表编辑器状态...");

                bool registryEditorDisabled = false;

                // 检查当前用户策略
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System"))
                {
                    if (key != null)
                    {
                        var disableRegistryTools = key.GetValue("DisableRegistryTools");
                        if (disableRegistryTools?.ToString() == "1")
                        {
                            registryEditorDisabled = true;
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
                        }
                    }
                }

                if (registryEditorDisabled)
                {
                    await AddRiskItem("注册表编辑器被禁用", "注册表编辑器已被系统策略禁用", @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System", "高危", "\uE783", "#D32F2F");
                }

                await Task.Delay(500, cancellationToken);
            }
            catch (Exception ex)
            {
                await AddRiskItem("注册表扫描失败", $"无法扫描注册表编辑器相关注册表: {ex.Message}", "注册表", "高危", "\uE783", "#D32F2F");
            }
        }

        private async Task ScanCommandPromptRegistry(CancellationToken cancellationToken)
        {
            await UpdateScanStatus("正在扫描命令提示符相关注册表...");
            await UpdateProgress(45);
            await Task.Delay(800, cancellationToken);

            try
            {
                // 检查命令提示符是否被禁用
                await UpdateScanStatus("检查命令提示符状态...");

                bool commandPromptDisabled = false;

                // 检查当前用户策略
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Policies\Microsoft\Windows\System"))
                {
                    if (key != null)
                    {
                        var disableCMD = key.GetValue("DisableCMD");
                        if (disableCMD?.ToString() == "1")
                        {
                            commandPromptDisabled = true;
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
                        }
                    }
                }

                if (commandPromptDisabled)
                {
                    await AddRiskItem("命令提示符被禁用", "命令提示符已被系统策略禁用", @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System", "高危", "\uE783", "#D32F2F");
                }

                await Task.Delay(500, cancellationToken);
            }
            catch (Exception ex)
            {
                await AddRiskItem("注册表扫描失败", $"无法扫描命令提示符相关注册表: {ex.Message}", "注册表", "高危", "\uE783", "#D32F2F");
            }
        }

        private async Task UpdateProgress(double value)
        {
            if (Dispatcher != null)
            {
                await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                {
                    if (ScanProgressBar != null)
                        ScanProgressBar.Value = value;
                    if (ScanProgressText != null)
                        ScanProgressText.Text = $"{value:F1}%";
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
                    {
                        CurrentScanItem.Text = status;
                    }
                });
            }
        }

        private void SelectAll_Click(object sender, RoutedEventArgs e)
        {
            if (RiskItemsList.Items.Count > 0)
            {
                for (int i = 0; i < RiskItemsList.Items.Count; i++)
                {
                    RiskItemsList.SelectRange(new ItemIndexRange(i, 1));
                }
                if (RepairSummary != null)
                    RepairSummary.Text = $"已选择全部 {_riskItems.Count} 个问题";
            }
        }

        private async void RepairSelected_Click(object sender, RoutedEventArgs e)
        {
            var selectedItems = RiskItemsList.SelectedItems.Cast<RiskItem>().ToList();
            if (selectedItems.Count == 0)
            {
                var dialog = new ContentDialog
                {
                    Title = "提示",
                    Content = "请选择要修复的问题",
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
                    Title = "提示",
                    Content = "没有可修复的问题",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                };
                await dialog.ShowAsync();
                return;
            }

            var confirmDialog = new ContentDialog
            {
                Title = "确认修复",
                Content = $"确定要修复全部 {_riskItems.Count} 个问题吗？此操作可能会影响系统稳定性。",
                PrimaryButtonText = "确认修复",
                CloseButtonText = "取消",
                XamlRoot = XamlRoot,
                PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
            };

            if (await confirmDialog.ShowAsync() == ContentDialogResult.Primary)
            {
                await RepairItems(_riskItems.ToList());
            }
        }

        private async Task RepairItems(List<RiskItem> items)
        {
            var progressDialog = new ContentDialog
            {
                Title = "正在修复",
                Content = "正在修复选择的问题，请稍候...",
                CloseButtonText = "取消",
                XamlRoot = XamlRoot
            };

            _ = progressDialog.ShowAsync();

            try
            {
                int successCount = 0;

                foreach (var item in items)
                {
                    bool repaired = await RepairSingleItem(item);
                    if (repaired)
                    {
                        successCount++;
                        item.IsRepaired = true;
                    }
                }

                progressDialog.Hide();

                var resultDialog = new ContentDialog
                {
                    Title = "修复完成",
                    Content = $"成功修复 {successCount}/{items.Count} 个问题",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                };
                await resultDialog.ShowAsync();

                // 移除已修复的问题
                foreach (var item in items.ToList())
                {
                    if (item.IsRepaired)
                    {
                        _riskItems.Remove(item);
                    }
                }
                RiskItemsList.ItemsSource = null;
                RiskItemsList.ItemsSource = _riskItems;
                if (RepairSummary != null)
                    RepairSummary.Text = $"剩余 {_riskItems.Count} 个未修复问题";
            }
            catch (Exception ex)
            {
                progressDialog.Hide();

                var errorDialog = new ContentDialog
                {
                    Title = "修复失败",
                    Content = $"修复过程中发生错误: {ex.Message}",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                };
                await errorDialog.ShowAsync();
            }
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
                            if (key != null)
                            {
                                key.SetValue("HideIcons", 0, RegistryValueKind.DWord);
                            }
                        }
                        return true;

                    case "任务栏显示异常":
                        // 重建任务栏设置
                        using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3"))
                        {
                            if (key != null)
                            {
                                // 设置默认任务栏设置
                                byte[] defaultValue = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x00, 0x00, 0x00, 0x2E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x80, 0x07, 0x00, 0x00, 0x38, 0x04, 0x00, 0x00 };
                                key.SetValue("Settings", defaultValue, RegistryValueKind.Binary);
                            }
                        }
                        return true;

                    case "鼠标左右键颠倒":
                        using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Control Panel\Mouse"))
                        {
                            if (key != null)
                            {
                                key.SetValue("SwapMouseButtons", 0, RegistryValueKind.String);
                            }
                        }
                        return true;

                    case "任务管理器被禁用":
                        using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System"))
                        {
                            if (key != null)
                            {
                                // 检查值是否存在再删除
                                if (key.GetValue("DisableTaskMgr") != null)
                                {
                                    key.DeleteValue("DisableTaskMgr", false);
                                }
                            }
                        }
                        return true;

                    case "注册表编辑器被禁用":
                        using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\System"))
                        {
                            if (key != null)
                            {
                                // 检查值是否存在再删除
                                if (key.GetValue("DisableRegistryTools") != null)
                                {
                                    key.DeleteValue("DisableRegistryTools", false);
                                }
                            }
                        }
                        return true;

                    default:
                        return false;
                }
            }
            catch (Exception ex)
            {
                await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                {
                    var errorDialog = new ContentDialog
                    {
                        Title = "修复失败",
                        Content = $"修复 {item.Name} 时发生错误: {ex.Message}",
                        CloseButtonText = "确定",
                        XamlRoot = XamlRoot
                    };
                    _ = errorDialog.ShowAsync();
                });
                return false;
            }
        }

        #endregion
    }

    public sealed class ProcessInfo
    {
        public string Name { get; }
        public int Id { get; }
        public string Memory { get; }
        public long MemoryBytes { get; }
        public ProcessInfo(Process p)
        {
            Name = $"{p.ProcessName}.exe";
            Id = p.Id;
            MemoryBytes = p.WorkingSet64;
            Memory = $"{MemoryBytes / 1024 / 1024} MB";
        }
    }

    public sealed class RiskItem
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string Location { get; set; }
        public string RiskLevel { get; set; }
        public string RiskIcon { get; set; }
        public string RiskColor { get; set; }
        public bool IsRepaired { get; set; }
    }
}