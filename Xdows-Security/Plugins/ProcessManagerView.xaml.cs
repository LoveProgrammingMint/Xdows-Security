using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ProcessManagerSharp;

namespace Xdows_Security.Views
{
    public sealed partial class ProcessManagerView : UserControl
    {
        private List<ProcessInfoEx> _allProcesses = [];
        private readonly ProcessManager _pm;

        public ProcessManagerView()
        {
            this.InitializeComponent();
            _pm = new ProcessManager();
            SortCombo.SelectedIndex = 0;
            _ = RefreshProcesses();
        }

        private async Task RefreshProcesses()
        {
            try
            {
                var list = await Task.Run(() =>
                {
              
                    var processes = _pm.GetProcessList();
                    return processes.Select(p => new ProcessInfoEx(p, _pm))
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

        private async void Refresh_Click(object sender, RoutedEventArgs e)
        {
            // 刷新不需要特定的进程，直接刷新整个列表
            await RefreshProcesses();
        }

        private void SortCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
            => ApplyFilterAndSort();

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
            => ApplyFilterAndSort();

        private void ApplyFilterAndSort()
        {
            var keyword = SearchBox.Text?.Trim() ?? "";
            IEnumerable<ProcessInfoEx> filtered = _allProcesses;

            if (!string.IsNullOrEmpty(keyword))
            {
                if (uint.TryParse(keyword, out var pid))
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
            var info = GetProcessInfoFromSender(sender);
            if (info == null) return;

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
            AddLine("父进程ID", info.ParentId.ToString());
            AddLine("会话ID", info.SessionId.ToString());
            AddLine("使用内存", info.Memory);
            AddLine("私有内存", info.PrivateMemory);
            AddLine("线程数", info.ThreadCount.ToString());
            AddLine("句柄数", info.HandleCount.ToString());
            AddLine("优先级", info.PriorityClass.ToString());
            AddLine("架构", info.IsWow64 ? "32位 (WOW64)" : "64位");
            AddLine("受保护", info.IsProtected ? "是" : "否");
            AddLine("被调试", info.IsBeingDebugged ? "是" : "否");

          
            if (!string.IsNullOrEmpty(info.ImagePath))
            {
                AddLine("文件路径", info.ImagePath);

                try
                {
                    var fi = new FileInfo(info.ImagePath);
                    if (fi.Exists)
                    {
                        AddLine("创建时间", fi.CreationTime.ToString("yyyy-MM-dd HH:mm:ss"));
                        AddLine("修改时间", fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"));
                        AddLine("文件大小", $"{fi.Length / 1024.0 / 1024.0:F2} MB");

                        var versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(fi.FullName);
                        AddLine("文件版本", versionInfo.FileVersion ?? "-");
                        AddLine("产品版本", versionInfo.ProductVersion ?? "-");
                        AddLine("公司名称", versionInfo.CompanyName ?? "-");
                        AddLine("产品名称", versionInfo.ProductName ?? "-");
                        AddLine("文件描述", versionInfo.FileDescription ?? "-");
                    }
                }
                catch { }
            }
            else
            {
                AddLine("文件路径", "拒绝访问或已退出");
            }

           
            if (!string.IsNullOrEmpty(info.CommandLine))
            {
                AddLine("命令行", info.CommandLine);
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
                SecondaryButtonText = "结束进程",
                RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
            };

            var result = await dialog.ShowAsync();

            if (result == ContentDialogResult.Primary)
            {
            
                if (string.IsNullOrEmpty(info.ImagePath))
                {
                    await new ContentDialog
                    {
                        Title = "无法定位文件",
                        Content = "无法访问此进程的文件路径。",
                        CloseButtonText = "确定",
                        RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                        XamlRoot = this.XamlRoot,
                        CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                    }.ShowAsync();
                }
                else
                {
                    try
                    {
                        var safeFilePath = info.ImagePath.Replace("\"", "\\\"");
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
            else if (result == ContentDialogResult.Secondary)
            {
               
                await KillProcessAsync(info);
            }
        }

        private IEnumerable<ProcessInfoEx> ApplySort(IEnumerable<ProcessInfoEx> src)
        {
            var tag = (SortCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Name";
            return tag switch
            {
                "Id" => src.OrderBy(p => p.Id),
                "Memory" => src.OrderByDescending(p => p.MemoryBytes),
                "Threads" => src.OrderByDescending(p => p.ThreadCount),
                "Handles" => src.OrderByDescending(p => p.HandleCount),
                _ => src.OrderBy(p => p.Name)
            };
        }

        private async void Kill_Click(object sender, RoutedEventArgs e)
        {
            var info = GetProcessInfoFromSender(sender);
            if (info == null) return;
            await KillProcessAsync(info);
        }

        private ProcessInfoEx? GetProcessInfoFromSender(object sender)
        {
          
            if (sender is MenuFlyoutItem menuItem)
            {
                return menuItem.DataContext as ProcessInfoEx;
            }
     
            return ProcessList.SelectedItem as ProcessInfoEx;
        }

        private async Task KillProcessAsync(ProcessInfoEx info)
        {
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

            var result = await Task.Run(() => TryKill(info.Id));

            if (result.Success)
            {
                await new ContentDialog
                {
                    Title = "结束成功",
                    Content = $"进程 {info.Name} 已成功结束。",
                    CloseButtonText = "确定",
                    RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    XamlRoot = this.XamlRoot,
                    CloseButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"]
                }.ShowAsync();
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

        private KillResult TryKill(uint pid)
        {
            try
            {
           
                _pm.TerminateProcess(pid, 0);
                return new KillResult { Success = true };
            }
            catch (ProcessManagerException ex)
            {
                return new KillResult { Success = false, Error = ex.Message };
            }
            catch (Exception ex)
            {
                return new KillResult { Success = false, Error = ex.Message };
            }
        }

        private async void Suspend_Click(object sender, RoutedEventArgs e)
        {
            var info = GetProcessInfoFromSender(sender);
            if (info == null) return;

            var result = await Task.Run(() =>
            {
                try
                {
                    _pm.SuspendProcess(info.Id);
                    return (Success: true, Error: "");
                }
                catch (ProcessManagerException ex)
                {
                    return (Success: false, Error: ex.Message);
                }
                catch (Exception ex)
                {
                    return (Success: false, Error: ex.Message);
                }
            });

            if (result.Success)
            {
                await new ContentDialog
                {
                    Title = "挂起成功",
                    Content = $"进程 {info.Name} 已挂起。",
                    CloseButtonText = "确定",
                    RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    XamlRoot = this.XamlRoot
                }.ShowAsync();
            }
            else
            {
                await new ContentDialog
                {
                    Title = "挂起失败",
                    Content = $"无法挂起进程: {result.Error}",
                    CloseButtonText = "确定",
                    RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    XamlRoot = this.XamlRoot
                }.ShowAsync();
            }
        }

        private async void Resume_Click(object sender, RoutedEventArgs e)
        {
            var info = GetProcessInfoFromSender(sender);
            if (info == null) return;

            var result = await Task.Run(() =>
            {
                try
                {
                    _pm.ResumeProcess(info.Id);
                    return (Success: true, Error: "");
                }
                catch (ProcessManagerException ex)
                {
                    return (Success: false, Error: ex.Message);
                }
                catch (Exception ex)
                {
                    return (Success: false, Error: ex.Message);
                }
            });

            if (result.Success)
            {
                await new ContentDialog
                {
                    Title = "恢复成功",
                    Content = $"进程 {info.Name} 已恢复。",
                    CloseButtonText = "确定",
                    RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    XamlRoot = this.XamlRoot
                }.ShowAsync();
            }
            else
            {
                await new ContentDialog
                {
                    Title = "恢复失败",
                    Content = $"无法恢复进程: {result.Error}",
                    CloseButtonText = "确定",
                    RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default,
                    XamlRoot = this.XamlRoot
                }.ShowAsync();
            }
        }

        private record KillResult
        {
            public bool Success { get; init; }
            public string Error { get; init; } = "";
        }
    }

    public sealed class ProcessInfoEx
    {
        public string Name { get; }
        public uint Id { get; }
        public uint ParentId { get; }
        public uint SessionId { get; }
        public string Memory { get; }
        public string PrivateMemory { get; }
        public long MemoryBytes { get; }
        public uint ThreadCount { get; }
        public uint HandleCount { get; }
        public uint PriorityClass { get; }
        public bool IsWow64 { get; }
        public bool IsProtected { get; }
        public bool IsBeingDebugged { get; }
        public string ImagePath { get; }
        public string CommandLine { get; }

        public ProcessInfoEx(ProcessManagerSharp.ProcessInfo p, ProcessManager pm)
        {
            var processName = p.ProcessName ?? "";
            if (string.IsNullOrEmpty(processName))
            {
 
                if (!string.IsNullOrEmpty(p.ImagePath))
                {
                    Name = System.IO.Path.GetFileName(p.ImagePath);
                }
                else
                {
                    Name = $"PID {p.ProcessId}";
                }
            }
            else
            {
                Name = processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? processName
                    : $"{processName}.exe";
            }

            Id = p.ProcessId;
            ParentId = p.ParentProcessId;
            SessionId = p.SessionId;
            ThreadCount = p.ThreadCount;
            HandleCount = p.HandleCount;
            PriorityClass = p.PriorityClass;
            IsWow64 = p.IsWow64;
            IsProtected = p.IsProtected;
            IsBeingDebugged = p.IsBeingDebugged;
            ImagePath = p.ImagePath ?? "";
            CommandLine = p.CommandLine ?? "";

            try
            {
                var memInfo = pm.GetProcessMemoryInfo(p.ProcessId);
                MemoryBytes = (long)memInfo.WorkingSetSize;
                Memory = $"{MemoryBytes / 1024 / 1024} MB";
                PrivateMemory = $"{memInfo.PrivateUsageMB:F2} MB";
            }
            catch
            {
                MemoryBytes = 0;
                Memory = "N/A";
                PrivateMemory = "N/A";
            }
        }
    }
}
