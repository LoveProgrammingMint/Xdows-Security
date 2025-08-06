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
                ProcessList.ItemsSource = Process.GetProcesses()
                                                 .Select(p => new ProcessInfo(p))
                                                 .OrderBy(p => p.Name)
                                                 .ToList();
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
        {
            if (ProcessList.ItemsSource is IEnumerable<ProcessInfo> src)
                ProcessList.ItemsSource = ApplySort(src).ToList();
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

            var result = TryKill(info.Id);
            if (!result.Success)
            {
                await new ContentDialog
                {
                    Title = "结束失败",
                    Content = result.Error,
                    CloseButtonText = "确定",
                    XamlRoot = XamlRoot
                }.ShowAsync();
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
                return new KillResult { Success = false, Error = "拒绝访问：无法结束此进程。" };
            }
            catch (UnauthorizedAccessException)
            {
                return new KillResult { Success = false, Error = "没有足够权限结束该进程。" };
            }
            catch (InvalidOperationException)
            {
                return new KillResult { Success = false, Error = "进程已退出。" };
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