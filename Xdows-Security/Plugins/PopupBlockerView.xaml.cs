using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Xdows_Security.Views
{
    public sealed partial class PopupBlockerView : UserControl
    {
        private List<PopupRule> _popupRules = new();
        private readonly PopupBlocker _popupBlocker = new();
        private bool _isPopupBlockingEnabled = false;

        public PopupBlockerView()
        {
            this.InitializeComponent();
            PopupSortCombo.SelectedIndex = 0;
            InitializePopupRules();
        }

        private void InitializePopupRules()
        {
            _popupRules = new List<PopupRule> { };
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
                XamlRoot = this.XamlRoot,
                RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
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
                XamlRoot = this.XamlRoot,
                RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
            };

            if (await confirm.ShowAsync() == ContentDialogResult.Primary)
            {
                _popupRules.Remove(rule);
                ApplyPopupFilterAndSort();
                UpdatePopupBlocking();
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
                XamlRoot = this.XamlRoot,
                RequestedTheme = (this.XamlRoot.Content as FrameworkElement)?.RequestedTheme ?? ElementTheme.Default
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
                }
            }
        }

        private void PopupRuleToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (sender is ToggleSwitch toggle && toggle.DataContext is PopupRule rule)
            {
                rule.IsEnabled = toggle.IsOn;
                UpdatePopupBlocking();
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
                }
                else
                {
                    _popupBlocker.UpdateRules(enabledRules);
                }
            }
            else
            {
                if (_isPopupBlockingEnabled)
                {
                    _popupBlocker.Stop();
                    _isPopupBlockingEnabled = false;
                }
            }
        }

        private void RefreshPopupList_Click(object sender, RoutedEventArgs e)
        {
            ApplyPopupFilterAndSort();
            UpdatePopupBlocking();
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
            _monitorTask = Task.Run(async () => await MonitorLoop(_cts.Token), _cts.Token);
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

        private async Task MonitorLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Run(() =>
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
                                        PostMessage(hWnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
                                        break;
                                    }
                                }
                            }
                            return true;
                        }, IntPtr.Zero);
                    }, token);
                }
                catch
                {
                }

                try
                {
                    await Task.Delay(500, token);
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

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        private static extern int GetWindowTextLength(IntPtr hWnd);

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        private static extern bool IsIconic(IntPtr hWnd);

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        private static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        private const uint WM_CLOSE = 0x0010;
    }
}
