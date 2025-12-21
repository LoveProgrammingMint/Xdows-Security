using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Xdows_Security.Views
{
    public sealed partial class ProcessManagerView : UserControl
    {
        private List<ProcessInfo> _allProcesses = new();

        public ProcessManagerView()
        {
            this.InitializeComponent();
            SortCombo.SelectedIndex = 0;
            _ = RefreshProcesses();
        }

        private async Task RefreshProcesses()
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
                    RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    XamlRoot = this.XamlRoot
                };

                await dialog.ShowAsync();
            }
        }

        private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshProcesses();

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
            catch { }

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
                    var fi = new FileInfo(filePath);
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
                XamlRoot = this.XamlRoot,
                PrimaryButtonText = "定位文件",
                RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
            };

            if (await dialog.ShowAsync() == ContentDialogResult.Primary)
            {
                try
                {
                    var safeFilePath = filePath.Replace("\"", "\\\"");
                    var psi = new ProcessStartInfo
                    {
                        FileName = "explorer.exe",
                        Arguments = $"/select,\"{safeFilePath}\"",
                        UseShellExecute = true
                    };
                    Process.Start(psi);
                }
                catch (Exception ex)
                {
                    await new ContentDialog
                    {
                        Title = "无法定位文件",
                        Content = $"无法定位文件，因为{ex.Message}",
                        CloseButtonText = "确定",
                        RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
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

        private async void Kill_Click(object sender, RoutedEventArgs e)
        {
            if (ProcessList.SelectedItem is not ProcessInfo info) return;

            var confirm = new ContentDialog
            {
                Title = $"你希望结束 {info.Name} ({info.Id}) 吗？",
                Content = "如果某个打开的程序与此进程关联，则会关闭此程序并且将丢失所有未保存的数据。如果结束某个系统进程，则可能导致系统不稳定。你确定要继续吗？",
                PrimaryButtonText = "结束",
                CloseButtonText = "取消",
                XamlRoot = this.XamlRoot,
                RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
            };
            if (await confirm.ShowAsync() != ContentDialogResult.Primary) return;

            var result = TryKill(info.Id);
            if (result.Success)
            {
            }
            else
            {
                await new ContentDialog
                {
                    Title = "结束失败",
                    Content = $"不能结束这个进程，因为 {result.Error}。",
                    CloseButtonText = "确定",
                    RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    XamlRoot = this.XamlRoot,
                    CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                }.ShowAsync();
            }
            await RefreshProcesses();
        }

        private static KillResult TryKill(int pid)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                p.Kill();
                return new KillResult { Success = true };
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception || ex is UnauthorizedAccessException || ex is InvalidOperationException)
            {
                return new KillResult { Success = false, Error = ex.Message };
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
