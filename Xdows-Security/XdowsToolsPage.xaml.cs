using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
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
            RefreshProcesses();
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
                // 全数字 → PID 精确匹配；否则 → 进程名模糊匹配
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
            TabTitle.Text = (e.AddedItems.FirstOrDefault() as TabViewItem)?.Header?.ToString();
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
        // 命令提示符
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

            await _cmdProcess!.StandardInput.WriteLineAsync(cmd);
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
}