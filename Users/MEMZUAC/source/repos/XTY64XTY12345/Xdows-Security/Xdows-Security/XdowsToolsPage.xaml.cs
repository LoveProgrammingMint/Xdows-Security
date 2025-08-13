using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;
using Microsoft.Win32;

namespace Xdows_Security
{
    public sealed partial class XdowsToolsPage : Page
    {
        private List<ProcessInfo> _allProcesses = new();
        private List<string> _commandHistory = new();
        private int _historyIndex = -1;
        private string _currentInput = string.Empty;

        // 系统修复相关字段
        private CancellationTokenSource _repairCancellationTokenSource;
        private List<RiskItem> _riskItems = new();
        private bool _isScanning = false;
        private bool _isInitialized = false;

        public XdowsToolsPage()
        {
            InitializeComponent();
            SortCombo.SelectedIndex = 0;
            RefreshProcesses();
            CmdOutput.Text = "安全命令行已经准备就绪，请输入相关命令并点击执行按钮或Enter执行。\r\n";
            // 移除构造函数中的UI控件访问，改在Loaded事件中处理
        }

        private void Page_Loaded(object sender, RoutedEventArgs e)
        {
            // 在页面完全加载后再设置UI控件
            if (RepairTabTitle != null)
            {
                RepairTabTitle.Text = "注册表修复工具";
            }
            _isInitialized = true;
        }

        private void RefreshProcesses()
        {
            try
            {
                _allProcesses = Process.GetProcesses()
                                       .Select(p => new ProcessInfo(p))
                                       .OrderBy(p => p.Name)
                                       .ToList();
                ApplyFilterAndSort();
            }
            catch (Exception ex)
            {
                _ = new ContentDialog
                {
                    Title = "刷新失败",
                    Content = ex.Message,
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                }.ShowAsync();
            }
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshProcesses();

        private void SortCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
            => ApplyFilterAndSort();

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
            => ApplyFilterAndSort();

        private void ApplyFilterAndSort()
        {
            var keyword = SearchBox.Text?.Trim() ?? "";
            IEnumerable<ProcessInfo> filtered = _allProcesses;

            if (!string.IsNullOrEmpty(keyword))
            {
                // 全匹配 PID 精确匹配；其他 模糊匹配
                if (int.TryParse(keyword, out var pid))
                {
                    filtered = _allProcesses.Where(p => p.Id == pid);
                }
                else
                {
                    filtered = _allProcesses
                        .Where(p => p.Name.Contains(keyword, StringComparison.OrdinalIgnoreCase));
                }
            }

            ProcessList.ItemsSource = ApplySort(filtered).ToList();
        }

        private IEnumerable<ProcessInfo> ApplySort(IEnumerable<ProcessInfo> src)
        {
            var tag = (SortCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Name";
            return tag switch
            {
                "Id" => src.OrderBy(p => p.Id),
                "Memory" => src.OrderByDescending(p => p.MemoryBytes),
                _ => src.OrderBy(p => p.Name)
            };
        }

        private void TabView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var selectedTab = e.AddedItems.FirstOrDefault() as TabViewItem;
            if (selectedTab != null)
            {
                TabTitle.Text = selectedTab.Header?.ToString();
                CmdTabTitle.Text = selectedTab.Header?.ToString();
            }
        }

        private async void Kill_Click(object sender, RoutedEventArgs e)
        {
            if (ProcessList.SelectedItem is not ProcessInfo info) return;

            var confirm = new ContentDialog
            {
                Title = $"您希望结束 {info.Name} ({info.Id}) 吗？",
                Content = "某些打开的程序可能会因此关闭。关闭此程序可能会导致未保存的数据丢失。如果您结束的是系统进程，可能会导致系统不稳定。确定要继续？",
                PrimaryButtonText = "结束",
                CloseButtonText = "取消",
                XamlRoot = XamlRoot,
                PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
            };
            if (await confirm.ShowAsync() != ContentDialogResult.Primary) return;
            LogText.AddNewLog(1, "Xdows Tools - KillProgress", $"{info.Name}({info.Id})", false);

            var result = TryKill(info.Id);
            if (result.Success)
            {
                LogText.AddNewLog(1, "Xdows Tools - KillProgress - Result", "Termination Successful", false);
            }
            else
            {
                await new ContentDialog
                {
                    Title = "结束失败",
                    Content = $"不能结束此进程，因为 {result.Error}。",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot,
                    CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                }.ShowAsync();
                LogText.AddNewLog(2, "Xdows Tools - KillProgress - Result", $"Cannot terminate this process because {result.Error}", false);
            }
            RefreshProcesses();
        }

        [DebuggerHidden]
        private static KillResult TryKill(int pid)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                p.Kill();
                return new KillResult { Success = true };
            }
            catch (Win32Exception)
            {
                return new KillResult { Success = false, Error = "拒绝访问" };
            }
            catch (UnauthorizedAccessException)
            {
                return new KillResult { Success = false, Error = "没有足够权限结束此进程" };
            }
            catch (InvalidOperationException)
            {
                return new KillResult { Success = false, Error = "进程已退出" };
            }
            catch (Exception ex)
            {
                return new KillResult { Success = false, Error = ex.Message };
            }
        }

        private record KillResult
        {
            public bool Success { get; init; }
            public string Error { get; init; } = "";
        }

        // CMD功能相关方法
        private void CmdInput_KeyDown(object sender, KeyRoutedEventArgs e)
        {
            if (e.Key == Windows.System.VirtualKey.Enter)
            {
                ExecuteCommand();
                e.Handled = true;
            }
            else if (e.Key == Windows.System.VirtualKey.Up)
            {
                NavigateHistory(-1);
                e.Handled = true;
            }
            else if (e.Key == Windows.System.VirtualKey.Down)
            {
                NavigateHistory(1);
                e.Handled = true;
            }
        }

        private void ExecuteButton_Click(object sender, RoutedEventArgs e)
        {
            ExecuteCommand();
        }

        private async void ExecuteCommand()
        {
            var command = CmdInput.Text?.Trim();
            if (string.IsNullOrEmpty(command)) return;

            // 添加到历史记录
            if (_commandHistory.Count == 0 || _commandHistory[_commandHistory.Count - 1] != command)
            {
                _commandHistory.Add(command);
                if (_commandHistory.Count > 50) // 限制历史记录数量
                {
                    _commandHistory.RemoveAt(0);
                }
            }
            _historyIndex = _commandHistory.Count;
            _currentInput = string.Empty;

            // 显示命令
            CmdOutput.Text += $"C:\> {command}\r\n";
            CmdInput.Text = string.Empty;

            // 执行命令
            try
            {
                var output = await ExecuteCommandAsync(command);
                CmdOutput.Text += output + "\r\n";
            }
            catch (Exception ex)
            {
                CmdOutput.Text += $"错误: {ex.Message}\r\n";
            }

            // 滚动到底部
            CmdOutput.ScrollToVerticalOffset(CmdOutput.ExtentHeight);
        }

        private async Task<string> ExecuteCommandAsync(string command)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/C {command}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System)
            };

            using var process = new Process { StartInfo = startInfo };
            var output = new StringBuilder();
            var error = new StringBuilder();

            process.OutputDataReceived += (s, e) =>
            {
                if (e.Data != null)
                {
                    output.AppendLine(e.Data);
                }
            };

            process.ErrorDataReceived += (s, e) =>
            {
                if (e.Data != null)
                {
                    error.AppendLine(e.Data);
                }
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            await Task.Run(() => process.WaitForExit());

            var result = output.ToString();
            if (error.Length > 0)
            {
                result += "\r\n错误输出:\r\n" + error.ToString();
            }

            return result;
        }

        private void NavigateHistory(int direction)
        {
            if (_commandHistory.Count == 0) return;

            if (direction == -1) // Up
            {
                if (_historyIndex > 0)
                {
                    if (_historyIndex == _commandHistory.Count)
                    {
                        _currentInput = CmdInput.Text;
                    }
                    _historyIndex--;
                    CmdInput.Text = _commandHistory[_historyIndex];
                }
            }
            else if (direction == 1) // Down
            {
                if (_historyIndex < _commandHistory.Count - 1)
                {
                    _historyIndex++;
                    CmdInput.Text = _commandHistory[_historyIndex];
                }
                else if (_historyIndex == _commandHistory.Count - 1)
                {
                    _historyIndex = _commandHistory.Count;
                    CmdInput.Text = _currentInput;
                }
            }
        }

        private void ClearOutput_Click(object sender, RoutedEventArgs e)
        {
            CmdOutput.Text = "输出已清空。\r\n";
        }

        private async void CopyOutput_Click(object sender, RoutedEventArgs e)
        {
            var dataPackage = new DataPackage();
            dataPackage.SetText(CmdOutput.Text);
            Clipboard.SetContent(dataPackage);

            var dialog = new ContentDialog
            {
                Title = "复制成功",
                Content = "输出内容已复制到剪贴板。",
                CloseButtonText = "确定",
                XamlRoot = XamlRoot
            };
            await dialog.ShowAsync();
        }

        // 注册表修复相关方法
        private async void StartRepairScan_Click(object sender, RoutedEventArgs e)
        {
            // 检查页面是否已初始化
            if (!_isInitialized)
            {
                var dialog = new ContentDialog
                {
                    Title = "提示",
                    Content = "页面正在初始化，请稍后再试",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                };
                await dialog.ShowAsync();
                return;
            }

            if (_isScanning) return;

            // 检查关键UI控件是否为null
            if (ScanStatus == null || ScanProgressBar == null || ScanProgressText == null || 
                CurrentScanItem == null || RiskItemsList == null || RepairSummary == null)
            {
                var dialog = new ContentDialog
                {
                    Title = "错误",
                    Content = "UI控件未正确初始化，请重新加载页面",
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                };
                await dialog.ShowAsync();
                return;
            }

            _isScanning = true;
            _repairCancellationTokenSource = new CancellationTokenSource();
            _riskItems.Clear();
            RiskItemsList.ItemsSource = null;

            ScanStatus.Text = "正在扫描注册表...";
            ScanProgressBar.Value = 0;
            RepairSummary.Text = "正在进行注册表问题扫描...";

            try
            {
                await Task.Run(async () =>
                {
                    // 扫描桌面图标显示的注册表
                    await ScanDesktopRegistry(_repairCancellationTokenSource.Token);

                    // 扫描鼠标右键设置的注册表
                    await ScanMouseRegistry(_repairCancellationTokenSource.Token);

                    // 扫描任务管理器相关的注册表
                    await ScanTaskManagerRegistry(_repairCancellationTokenSource.Token);

                    // 扫描注册表编辑器相关的注册表
                    await ScanRegeditRegistry(_repairCancellationTokenSource.Token);
                });

                if (!_repairCancellationTokenSource.Token.IsCancellationRequested)
                {
                    await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                    {
                        // 再次检查UI控件是否为null
                        if (ScanStatus != null && ScanProgressBar != null && ScanProgressText != null && 
                            CurrentScanItem != null && RiskItemsList != null && RepairSummary != null)
                        {
                            ScanStatus.Text = "扫描完成";
                            ScanProgressBar.Value = 100;
                            ScanProgressText.Text = "100%";
                            CurrentScanItem.Text = "注册表扫描完成，发现 " + _riskItems.Count + " 个问题";
                            RiskItemsList.ItemsSource = _riskItems;
                            RepairSummary.Text = $"扫描完成，发现 {_riskItems.Count} 个注册表问题";
                        }
                        _isScanning = false;
                    });
                }
            }
            catch (Exception ex)
            {
                await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
                {
                    if (ScanStatus != null && CurrentScanItem != null && RepairSummary != null)
                    {
                        ScanStatus.Text = "扫描失败";
                        CurrentScanItem.Text = $"扫描过程中发生错误: {ex.Message}";
                        RepairSummary.Text = "扫描失败，请重试";
                    }
                    _isScanning = false;
                });
            }
        }

        private async Task UpdateProgress(double value)
        {
            await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
            {
                // 检查UI控件是否为null
                if (ScanProgressBar != null && ScanProgressText != null)
                {
                    ScanProgressBar.Value = value;
                    ScanProgressText.Text = $"{value:F1}%";
                }
            });
        }

        private async Task UpdateScanStatus(string status)
        {
            await Dispatcher.RunAsync(Windows.UI.Core.CoreDispatcherPriority.Normal, () =>
            {
                // 检查UI控件是否为null
                if (CurrentScanItem != null)
                {
                    CurrentScanItem.Text = status;
                }
            });
        }

        private void SelectAll_Click(object sender, RoutedEventArgs e)
        {
            // 检查UI控件是否为null
            if (RiskItemsList == null || RepairSummary == null) return;

            if (RiskItemsList.Items.Count > 0)
            {
                for (int i = 0; i < RiskItemsList.Items.Count; i++)
                {
                    RiskItemsList.SelectRange(new ItemIndexRange(i, 1));
                }
                RepairSummary.Text = $"已选择全部 {_riskItems.Count} 个问题";
            }
        }

        private async void RepairSelected_Click(object sender, RoutedEventArgs e)
        {
            // 检查UI控件是否为null
            if (RiskItemsList == null) return;

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
            // 检查UI控件是否为null
            if (RepairSummary == null) return;

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
                await RepairItems(_riskItems);
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
                    Title = "修复结果",
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
                
                // 检查UI控件是否为null
                if (RiskItemsList != null && RepairSummary != null)
                {
                    RiskItemsList.ItemsSource = null;
                    RiskItemsList.ItemsSource = _riskItems;
                    RepairSummary.Text = $"剩余 {_riskItems.Count} 个未修复问题";
                }
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
    }

    public class RiskItem
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