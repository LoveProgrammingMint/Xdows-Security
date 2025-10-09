using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Xdows_Security
{
    public sealed partial class XdowsToolsPage : Page
    {
        private List<ProcessInfo> _allProcesses = new();

        public XdowsToolsPage()
        {
            InitializeComponent();
            SortCombo.SelectedIndex = 0;
            PopupSortCombo.SelectedIndex = 0;
            RefreshProcesses();
            InitializePopupRules();
        }

        private async void RefreshProcesses()
        {
            try
            {
                var list = await Task.Run(() =>
                {
                    return Process.GetProcesses()
                                  .Select(p => new ProcessInfo(p))
                                  .OrderBy(p => p.Name)
                                  .ToList();
                });

                _allProcesses = list;
                ApplyFilterAndSort();
            }
            catch (Exception ex)
            {
                var dialog = new ContentDialog
                {
                    Title = "刷新失败",
                    Content = ex.Message,
                    CloseButtonText = "确定",
                    RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme,
                    XamlRoot = XamlRoot
                };

                await dialog.ShowAsync();
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
        private async void ShowProcessDetail_Click(object sender, RoutedEventArgs e)
        {
            if (ProcessList.SelectedItem is not ProcessInfo info) return;

            string filePath = string.Empty;
            try
            {
                using var p = System.Diagnostics.Process.GetProcessById(info.Id);
                filePath = p.MainModule?.FileName ?? string.Empty;
            }
            catch {}

            // 创建对话框内容
            var sp = new StackPanel { Spacing = 8 };
            void AddLine(string key, string value)
            {
                sp.Children.Add(new TextBlock
                {
                    Text = $"{key}: {value}",
                    IsTextSelectionEnabled = true,
                    TextWrapping = TextWrapping.Wrap
                });
            }

            AddLine("进程名称", info.Name);
            AddLine("进程编号", info.Id.ToString());
            AddLine("使用内存", info.Memory);

            if (!string.IsNullOrEmpty(filePath))
            {
                try
                {
                    var fi = new System.IO.FileInfo(filePath);
                    AddLine("创建时间", fi.CreationTime.ToString("yyyy-MM-dd HH:mm:ss"));
                    AddLine("修改时间", fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"));
                    AddLine("文件版本", System.Diagnostics.FileVersionInfo.GetVersionInfo(fi.FullName).FileVersion ?? "-");
                    AddLine("文件路径", fi.FullName);
                }
                catch { }
            }
            else
            {
                AddLine("文件路径", "拒绝访问或已退出");
            }

            var dialog = new ContentDialog
            {
                Title = "详细信息",
                Content = new ScrollViewer
                {
                    Content = sp,
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto
                },
                CloseButtonText = "关闭",
                XamlRoot = XamlRoot,
                PrimaryButtonText = "定位文件",
                RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme,
                CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
            };

            if (await dialog.ShowAsync() == ContentDialogResult.Primary)
            {
                try
                {
                    string? directoryPath = Path.GetDirectoryName(filePath);
                    string fileName = Path.GetFileName(filePath);

                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "explorer.exe",
                        Arguments = $"/select,\"{filePath}\""
                    };
                    System.Diagnostics.Process.Start(psi);
                }
                catch (Exception ex)
                {
                    await new ContentDialog
                    {
                        Title = "无法定位文件",
                        Content = $"无法定位文件，因为{ex.Message}",
                        CloseButtonText = "确定",
                        RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme,
                        XamlRoot = this.XamlRoot,
                        CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                    }.ShowAsync();
                }
            }
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
            TabTitle.Text = selectedTab?.Header?.ToString();
            
            if (selectedTab?.Header?.ToString() == "弹窗拦截")
            {
                PopupTabTitle.Text = "弹窗拦截器";
            }
        }

        private async void Kill_Click(object sender, RoutedEventArgs e)
        {
            if (ProcessList.SelectedItem is not ProcessInfo info) return;

            var confirm = new ContentDialog
            {
                Title = $"你希望结束 {info.Name} ({info.Id}) 吗？",
                Content = "如果某个打开的程序与此进程关联，则会关闭此程序并且将丢失所有未保存的数据。如果结束某个系统进程，则可能导致系统不稳定。你确定要继续吗？",
                PrimaryButtonText = "结束",
                CloseButtonText = "取消",
                XamlRoot = XamlRoot,
                RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme,
                PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
            };
            if (await confirm.ShowAsync() != ContentDialogResult.Primary) return;
            LogText.AddNewLog(1, "Xdows Tools - KillProgress", $"{info.Name}({info.Id})");

            var result = TryKill(info.Id);
            if (result.Success)
            {
                LogText.AddNewLog(1, "Xdows Tools - KillProgress - Result", "Termination Successful");
            }
            else
            {
                await new ContentDialog
                {
                    Title = "结束失败",
                    Content = $"不能结束这个进程，因为 {result.Error}。",
                    CloseButtonText = "确定",
                    RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme,
                    XamlRoot = XamlRoot,
                    CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                }.ShowAsync();
                LogText.AddNewLog(2, "Xdows Tools - KillProgress - Result", $"Cannot terminate this process because {result.Error}");
            }
            RefreshProcesses();
        }

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
                return new KillResult { Success = false, Error = "没有足够权限结束该进程" };
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
        private void RepairAll_Click(object sender, RoutedEventArgs e) { }
        private void SelectAll_Click(object sender, RoutedEventArgs e) { }
        private void StartRepairScan_Click(object sender, RoutedEventArgs e) { }
        private void StopRepairScan_Click(object sender, RoutedEventArgs e) { }
        private void Page_Loaded(object sender, RoutedEventArgs e) { }
        private void RepairSelected_Click(object sender, RoutedEventArgs e) { }

        private List<PopupRule> _popupRules = new();
        private List<PopupRule> _filteredPopupRules = new();
        private PopupBlocker _popupBlocker = new();
        private bool _isPopupBlockingEnabled = false;

        private void InitializePopupRules()
        {
            _popupRules = new List<PopupRule>{};
            ApplyPopupFilterAndSort();
        }

        private void PopupSortCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
            => ApplyPopupFilterAndSort();

        private void PopupSearchBox_TextChanged(object sender, TextChangedEventArgs e)
            => ApplyPopupFilterAndSort();

        private void ApplyPopupFilterAndSort()
        {
            var keyword = PopupSearchBox.Text?.Trim() ?? "";
            IEnumerable<PopupRule> filtered = _popupRules;

            if (!string.IsNullOrEmpty(keyword))
            {
                filtered = _popupRules
                    .Where(p => p.Title.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                               p.ProcessName.Contains(keyword, StringComparison.OrdinalIgnoreCase));
            }

            PopupRuleList.ItemsSource = ApplyPopupSort(filtered).ToList();
        }

        private IEnumerable<PopupRule> ApplyPopupSort(IEnumerable<PopupRule> src)
        {
            var tag = (PopupSortCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Title";
            return tag switch
            {
                "Status" => src.OrderBy(p => p.Status),
                "Process" => src.OrderBy(p => p.ProcessName),
                _ => src.OrderBy(p => p.Title)
            };
        }

        private async void AddPopupRule_Click(object sender, RoutedEventArgs e)
        {
            var titleTextBox = new TextBox { PlaceholderText = "输入要拦截的弹窗标题", Margin = new Thickness(0, 0, 0, 16) };
            var processTextBox = new TextBox { PlaceholderText = "输入进程名称（可选）", Margin = new Thickness(0, 0, 0, 16) };
            var enabledToggle = new ToggleSwitch { IsOn = true };

            var dialog = new ContentDialog
            {
                Title = "添加弹窗拦截规则",
                Content = new StackPanel
                {
                    Children =
                    {
                        new TextBlock { Text = "弹窗标题:", Margin = new Thickness(0, 0, 0, 8) },
                        titleTextBox,
                        new TextBlock { Text = "进程名称:", Margin = new Thickness(0, 0, 0, 8) },
                        processTextBox,
                        new TextBlock { Text = "是否启用:", Margin = new Thickness(0, 0, 0, 8) },
                        enabledToggle
                    }
                },
                PrimaryButtonText = "添加",
                CloseButtonText = "取消",
                XamlRoot = XamlRoot,
                RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme
            };

            if (await dialog.ShowAsync() == ContentDialogResult.Primary)
            {
                if (!string.IsNullOrWhiteSpace(titleTextBox.Text))
                {
                    var newRule = new PopupRule
                    {
                        Title = titleTextBox.Text.Trim(),
                        ProcessName = string.IsNullOrWhiteSpace(processTextBox.Text) ? "*" : processTextBox.Text.Trim(),
                        IsEnabled = enabledToggle.IsOn
                    };

                    _popupRules.Add(newRule);
                    ApplyPopupFilterAndSort();
                    UpdatePopupBlocking();
                    LogText.AddNewLog(1, "Xdows Tools - PopupBlocker", $"Added rule: {newRule.Title}");
                }
            }
        }

        private async void DeletePopupRule_Click(object sender, RoutedEventArgs e)
        {
            if (PopupRuleList.SelectedItem is not PopupRule rule) return;

            var confirm = new ContentDialog
            {
                Title = $"删除规则",
                Content = $"确定要删除规则 \"{rule.Title}\" 吗？",
                PrimaryButtonText = "删除",
                CloseButtonText = "取消",
                XamlRoot = XamlRoot,
                RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme
            };

            if (await confirm.ShowAsync() == ContentDialogResult.Primary)
            {
                _popupRules.Remove(rule);
                ApplyPopupFilterAndSort();
                UpdatePopupBlocking();
                LogText.AddNewLog(1, "Xdows Tools - PopupBlocker", $"Deleted rule: {rule.Title}");
            }
        }

        private async void EditPopupRule_Click(object sender, RoutedEventArgs e)
        {
            if (PopupRuleList.SelectedItem is not PopupRule rule) return;

            var titleTextBox = new TextBox { Text = rule.Title, Margin = new Thickness(0, 0, 0, 16) };
            var processTextBox = new TextBox { Text = rule.ProcessName, Margin = new Thickness(0, 0, 0, 16) };
            var enabledToggle = new ToggleSwitch { IsOn = rule.IsEnabled };

            var dialog = new ContentDialog
            {
                Title = "编辑弹窗拦截规则",
                Content = new StackPanel
                {
                    Children =
                    {
                        new TextBlock { Text = "弹窗标题:", Margin = new Thickness(0, 0, 0, 8) },
                        titleTextBox,
                        new TextBlock { Text = "进程名称:", Margin = new Thickness(0, 0, 0, 8) },
                        processTextBox,
                        new TextBlock { Text = "是否启用:", Margin = new Thickness(0, 0, 0, 8) },
                        enabledToggle
                    }
                },
                PrimaryButtonText = "保存",
                CloseButtonText = "取消",
                XamlRoot = XamlRoot,
                RequestedTheme = ((FrameworkElement)XamlRoot.Content).RequestedTheme
            };

            if (await dialog.ShowAsync() == ContentDialogResult.Primary)
            {
                if (!string.IsNullOrWhiteSpace(titleTextBox.Text))
                {
                    rule.Title = titleTextBox.Text.Trim();
                    rule.ProcessName = string.IsNullOrWhiteSpace(processTextBox.Text) ? "*" : processTextBox.Text.Trim();
                    rule.IsEnabled = enabledToggle.IsOn;

                    ApplyPopupFilterAndSort();
                    UpdatePopupBlocking();
                    LogText.AddNewLog(1, "Xdows Tools - PopupBlocker", $"Edited rule: {rule.Title}");
                }
            }
        }

        private void PopupRuleToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (sender is ToggleSwitch toggle && toggle.DataContext is PopupRule rule)
            {
                rule.IsEnabled = toggle.IsOn;
                UpdatePopupBlocking();
                LogText.AddNewLog(1, "Xdows Tools - PopupBlocker", $"Toggled rule: {rule.Title} - {rule.IsEnabled}");
            }
        }

        private void UpdatePopupBlocking()
        {
            var enabledRules = _popupRules.Where(r => r.IsEnabled).ToList();
            
            if (enabledRules.Any())
            {
                if (!_isPopupBlockingEnabled)
                {
                    _popupBlocker.Start(enabledRules);
                    _isPopupBlockingEnabled = true;
                    LogText.AddNewLog(1, "Xdows Tools - PopupBlocker", "Popup blocking enabled");
                }
                else
                {
                    _popupBlocker.UpdateRules(enabledRules);
                    LogText.AddNewLog(1, "Xdows Tools - PopupBlocker", "Popup rules updated");
                }
            }
            else
            {
                if (_isPopupBlockingEnabled)
                {
                    _popupBlocker.Stop();
                    _isPopupBlockingEnabled = false;
                    LogText.AddNewLog(1, "Xdows Tools - PopupBlocker", "Popup blocking disabled");
                }
            }
        }

        private void RefreshPopupList_Click(object sender, RoutedEventArgs e)
        {
            ApplyPopupFilterAndSort();
            UpdatePopupBlocking();
            LogText.AddNewLog(1, "Xdows Tools - PopupBlocker", "Refreshed popup rules list");
        }
        private readonly System.Text.StringBuilder _cmdOutputSb = new();
        private System.Diagnostics.Process? _cmdProcess;
        private bool _cmdRunning;

        private async void ExecuteButton_Click(object sender, RoutedEventArgs e)
        {
            var cmd = CmdInput.Text.Trim();
            if (string.IsNullOrWhiteSpace(cmd) || _cmdRunning == false && _cmdProcess?.HasExited == false) return;

            if (_cmdProcess == null || _cmdProcess.HasExited)
            {
                _cmdOutputSb.Clear();
                CmdOutput.Text = "命令提示符启动成功，请输入相关命令。";
                StartCmd();
            }
            try { 
            await _cmdProcess!.StandardInput.WriteLineAsync(cmd);
            }
            catch { }
            LogText.AddNewLog(1, "Xdows Tools - RunCommand", cmd);
            CmdInput.Text = string.Empty;
        }

        private void StartCmd()
        {
            if (_cmdProcess != null && !_cmdProcess.HasExited) return;

            _cmdProcess = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/k",
                    UseShellExecute = false,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                },
                EnableRaisingEvents = true
            };
            _cmdProcess.OutputDataReceived += OnOutput;
            _cmdProcess.ErrorDataReceived += OnOutput;
            _cmdProcess.Exited += (_, _) =>
            {
                _cmdRunning = false;
                AppendOutput("\n进程已退出。");
            };

            _cmdProcess.Start();
            _cmdProcess.BeginOutputReadLine();
            _cmdProcess.BeginErrorReadLine();
            _cmdRunning = true;
        }

        private void OnOutput(object? _, System.Diagnostics.DataReceivedEventArgs e)
        {
            if (e.Data != null) AppendOutput(e.Data);
        }

        private void AppendOutput(string text)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                _cmdOutputSb.AppendLine(text);
                CmdOutput.Text = _cmdOutputSb.ToString();
            });
        }

        private void ClearOutput_Click(object sender, RoutedEventArgs e)
        {
            _cmdOutputSb.Clear();
            CmdOutput.Text = string.Empty;
        }

        private void CopyOutput_Click(object sender, RoutedEventArgs e)
        {
            var dp = new Windows.ApplicationModel.DataTransfer.DataPackage();
            dp.SetText(CmdOutput.Text);
            Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(dp);
        }

        private void CmdInput_KeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
        {
            if (e.Key == Windows.System.VirtualKey.Enter)
            {
                e.Handled = true;
                ExecuteButton_Click(sender, e);
            }
        }
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

    public sealed class PopupRule
    {
        public string Title { get; set; } = "";
        public string ProcessName { get; set; } = "*";
        public bool IsEnabled { get; set; } = true;
        public string Status => IsEnabled ? "已启用" : "已禁用";
    }

    public class PopupBlocker
    {
        private CancellationTokenSource? _cts;
        private Task? _monitorTask;
        private List<PopupRule> _rules = new();

        public void Start(List<PopupRule> rules)
        {
            Stop();
            _rules = rules;
            _cts = new CancellationTokenSource();
            _monitorTask = Task.Run(() => MonitorLoop(_cts.Token), _cts.Token);
        }

        public void Stop()
        {
            if (_cts != null)
            {
                _cts.Cancel();
                _monitorTask?.Wait(1000);
                _cts.Dispose();
                _cts = null;
                _monitorTask = null;
            }
        }

        public void UpdateRules(List<PopupRule> rules)
        {
            _rules = rules;
        }

        private void MonitorLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    EnumWindows((hWnd, lParam) =>
                    {
                        if (IsWindowVisible(hWnd) && !IsIconic(hWnd))
                        {
                            var title = GetWindowTitle(hWnd);
                            var processName = GetWindowProcessName(hWnd);

                            foreach (var rule in _rules)
                            {
                                if (title.Contains(rule.Title, StringComparison.OrdinalIgnoreCase) &&
                                    (rule.ProcessName == "*" || processName.Contains(rule.ProcessName, StringComparison.OrdinalIgnoreCase)))
                                {
                                    LogText.AddNewLog(1, "Xdows Tools - PopupBlocker", $"Blocking popup: '{title}' from {processName}");
                                    PostMessage(hWnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
                                    break;
                                }
                            }
                        }
                        return true;
                    }, IntPtr.Zero);
                }
                catch
                {
                }

                try
                {
                    Task.Delay(500, token).Wait(token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        private string GetWindowTitle(IntPtr hWnd)
        {
            int length = GetWindowTextLength(hWnd);
            if (length == 0) return string.Empty;

            StringBuilder builder = new StringBuilder(length + 1);
            GetWindowText(hWnd, builder, builder.Capacity);
            return builder.ToString();
        }

        private string GetWindowProcessName(IntPtr hWnd)
        {
            GetWindowThreadProcessId(hWnd, out uint pid);
            try
            {
                using var process = Process.GetProcessById((int)pid);
                return process.ProcessName + ".exe";
            }
            catch
            {
                return "unknown.exe";
            }
        }

        // Windows API
        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        private const uint WM_CLOSE = 0x0010;
    }
}