using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.WindowsAPICodePack.Dialogs;
using System;
using System.IO;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Windows.System;
using WinUI3Localizer;

namespace Xdows_Security
{
    public sealed partial class BugReportPage : Page
    {
        private ClientWebSocket? _ws;
        private CancellationTokenSource? _cts;

        private string Loc(string key)
        {
            try
            {
                var s = Localizer.Get().GetLocalizedString(key);
                if (!string.IsNullOrEmpty(s)) return s;

                string[] suffixes = new[] { ".Text", ".Content", ".Header", ".Title", ".Description" };
                foreach (var suf in suffixes)
                {
                    s = Localizer.Get().GetLocalizedString(key + suf);
                    if (!string.IsNullOrEmpty(s)) return s;
                }

                return string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        public BugReportPage()
        {
            InitializeComponent();
            Loaded += (_, __) => _ = InitializeWebSocketAsync();
            Unloaded += (_, __) => Cleanup();
        }

        #region WebSocket
        private async Task InitializeWebSocketAsync()
        {
            Cleanup();
            _cts = new CancellationTokenSource();
            _ws = new ClientWebSocket();
            try
            {
                await _ws.ConnectAsync(new Uri("ws://103.118.245.82:8765"), _cts.Token);
                StatusTxt.Text = Loc("BugReportPage_Connected");
                _ = Task.Run(() => ReceiveLoopAsync(_cts.Token));
            }
            catch (Exception ex)
            {
                StatusTxt.Text = Loc("BugReportPage_ConnectionFailed");
                AddMessage(Loc("BugReportPage_ConnectionFailedMessage") + ex.Message, false);
            }
        }

        private async Task ReceiveLoopAsync(CancellationToken token)
        {
            await using var ms = new MemoryStream();
            var buffer = new ArraySegment<byte>(new byte[4 * 1024]);
            if (_ws == null) return;

            while (!token.IsCancellationRequested && _ws.State == WebSocketState.Open)
            {
                var result = await _ws.ReceiveAsync(buffer, token);
                if (result.MessageType == WebSocketMessageType.Text)
                {
                    ms.Write(buffer.Array!, buffer.Offset, result.Count);
                    if (result.EndOfMessage)
                    {
                        ms.Position = 0;
                        string json = Encoding.UTF8.GetString(ms.ToArray());

                        DispatcherQueue.TryEnqueue(() =>
                        {
                            if (!TryHandleFileMessage(json))
                                ExtractAndAddHistory(json,
                                                    (msg, isMe) => AddMessage(msg, isMe),
                                                    () => ScrollToBottom(force: true));
                        });

                        ms.SetLength(0);
                        ScrollToBottom(force: true);
                    }
                }
                else if (result.MessageType == WebSocketMessageType.Close)
                {
                    break;
                }
            }
        }
        #endregion

        #region 文件消息（发送+接收）
        private async void FileBtn_Click(object sender, RoutedEventArgs e)
        {
            // 1. 弹出原生打开对话框
            using var dlg = new CommonOpenFileDialog
            {
                Title = Loc("BugReportPage_SelectFileTitle"),
                Filters = { new CommonFileDialogFilter("所有文件", "*") }
            };

            if (dlg.ShowDialog() != CommonFileDialogResult.Ok) return;

            string fullPath = dlg.FileName;
            var info = new FileInfo(fullPath);

            // 2. 大小检查
            if (info.Length > 20 * 1024)          // 20 KB
            {
                AddMessage(Loc("BugReportPage_FileTooLarge"), true);
                return;
            }

            // 3. 读文件 → Base64
            byte[] bytes = File.ReadAllBytes(fullPath);
            string b64 = Convert.ToBase64String(bytes);

            // 4. 组装 JSON
            string fileJson = JsonSerializer.Serialize(new
            {
                type = "file",
                name = info.Name,
                sizeKB = Math.Ceiling(info.Length / 1024.0),
                fileB64 = b64
            });
            string payload = JsonSerializer.Serialize(new { type = "user", content = fileJson });

            // 5. WebSocket 发送
            if (_ws == null || _ws.State != WebSocketState.Open || _cts == null) return;
            await _ws.SendAsync(new ArraySegment<byte>(Encoding.UTF8.GetBytes(payload)),
                                WebSocketMessageType.Text, true, _cts.Token);

            AddMessage(Loc("BugReportPage_FileSent") + info.Name, true);
        }

        /// <summary>
        /// 安全尝试把一段文本当作“文件JSON”处理。
        /// 合法且保存成功后返回 true，否则 false（调用方应继续当普通文本）。
        /// </summary>
        private bool TryHandleFileMessage(string json)
        {
            if (string.IsNullOrWhiteSpace(json) || !json.TrimStart().StartsWith('{'))
                return false;

            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (root.TryGetProperty("type", out var t) && t.GetString() == "user" &&
                    root.TryGetProperty("content", out var c))
                {
                    return TryHandleFileMessage(c.GetString()!);
                }

                if (!root.TryGetProperty("type", out t) || t.GetString() != "file")
                    return false;
                if (!root.TryGetProperty("name", out var nameProp) ||
                    !root.TryGetProperty("fileB64", out var b64Prop))
                    return false;

                string name = nameProp.GetString()!;
                string b64 = b64Prop.GetString()!;
                byte[] data = Convert.FromBase64String(b64);

                double sizeKB = 0;
                if (root.TryGetProperty("sizeKB", out var sizeProp))
                    sizeKB = sizeProp.GetDouble();

                var card = new Border
                {
                    CornerRadius = new CornerRadius(12),
                    Padding = new Thickness(10, 8, 10, 8),
                    Margin = new Thickness(8, 4, 8, 4),
                    MaxWidth = 280,
                    HorizontalAlignment = HorizontalAlignment.Left,
                    Background = (Brush)Application.Current.Resources["CardBackgroundFillColorDefaultBrush"],
                    BorderBrush = (Brush)Application.Current.Resources["ControlElevationBorderBrush"],
                    BorderThickness = new Thickness(1)
                };

                var rootGrid = new Grid();
                rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

                var topGrid = new Grid { ColumnSpacing = 8 };
                topGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                topGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

                var icon = new FontIcon
                {
                    Glyph = "\uE8A5",
                    FontSize = 32,
                    VerticalAlignment = VerticalAlignment.Center,
                };

                var stack = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Spacing = 2 };
                var tbName = new TextBlock
                {
                    Text = name,
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    FontSize = 14
                };
                var tbSize = new TextBlock
                {
                    Text = $"{sizeKB:0.##} KB",
                    FontSize = 12,
                    Opacity = 0.7
                };
                stack.Children.Add(tbName);
                stack.Children.Add(tbSize);

                Grid.SetColumn(icon, 0);
                Grid.SetColumn(stack, 1);
                topGrid.Children.Add(icon);
                topGrid.Children.Add(stack);

                var btn = new Button
                {
                    Content = Loc("BugReportPage_DownloadAndLocate"),
                    Padding = new Thickness(8, 4, 8, 4),
                    FontSize = 12,
                    HorizontalAlignment = HorizontalAlignment.Stretch,
                    Margin = new Thickness(0, 6, 0, 0)
                };

                async void OpenFileHandler()
                {
                    string folder = Path.Combine(
                                        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                                        "Downloads");
                    Directory.CreateDirectory(folder);
                    string target = Path.Combine(folder, name);
                    File.WriteAllBytes(target, data);
                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "explorer.exe",
                    };
                    var safeTarget = target.Replace("\"", "\\\"");
                    psi.Arguments = $"/select,\"{safeTarget}\"";
                    System.Diagnostics.Process.Start(psi);
                }

                btn.Click += (_, _) => OpenFileHandler();

                Grid.SetRow(topGrid, 0);
                Grid.SetRow(btn, 1);
                rootGrid.Children.Add(topGrid);
                rootGrid.Children.Add(btn);

                card.Child = rootGrid;
                card.PointerPressed += (_, _) => OpenFileHandler();

                MessagesPanel.Children.Add(card);
                ScrollToBottom();
                return true;
            }
            catch (JsonException)
            {
                return false;
            }
        }
        #endregion

        #region 普通聊天
        private void ExtractAndAddHistory(string json,
                                          Action<string, bool> add,
                                          Action scrollToBottom)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (!root.TryGetProperty("type", out var t) ||
                    string.Equals(t.GetString(), "status", StringComparison.OrdinalIgnoreCase))
                    return;

                bool isHistory = t.ValueKind == JsonValueKind.String &&
                                 string.Equals(t.GetString(), "history", StringComparison.OrdinalIgnoreCase);

                if (!isHistory)
                {
                    if (root.TryGetProperty("content", out var c))
                        add(c.ToString(), false);
                    else
                        add(json, false);
                    return;
                }

                if (root.TryGetProperty("content", out var hist) && hist.ValueKind == JsonValueKind.Array)
                {
                    int total = hist.GetArrayLength(), count = 0;
                    foreach (var item in hist.EnumerateArray())
                    {
                        string innerText;
                        if (item.TryGetProperty("content", out var inner))
                            innerText = inner.ToString();
                        else
                            innerText = item.ToString();
                        if (!TryHandleFileMessage(innerText))
                            add(innerText, false);

                        if (++count == total)
                            scrollToBottom();
                    }
                }
                else
                {
                    add(json, false);
                    scrollToBottom();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[HistoryParseError] {ex.Message}\nRaw: {json}");
                add(json, false);
                scrollToBottom();
            }
        }

        private void AddMessage(string text, bool isMe)
        {
            var b = new Border
            {
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(12),
                Margin = new Thickness(8, 0, 0, 4),
                MaxWidth = 300,
                HorizontalAlignment = isMe ? HorizontalAlignment.Right : HorizontalAlignment.Left,
                BorderThickness = new Thickness(1),
                BorderBrush = (Brush)Application.Current.Resources["ControlElevationBorderBrush"],
                Background = (Brush)Application.Current.Resources[isMe
                                ? "SystemFillColorAttentionBrush"
                                : "CardBackgroundFillColorDefaultBrush"]
            };

            var richText = new RichTextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                IsTextSelectionEnabled = true,
                Foreground = isMe
                    ? new SolidColorBrush(Microsoft.UI.Colors.White)
                    : (Brush)Application.Current.Resources["TextFillColorPrimaryBrush"]
            };

            var paragraph = new Paragraph();
            var parts = Regex.Split(text, @"((?:https?|ftp)://[^\s]+)");
            foreach (var part in parts)
            {
                if (Regex.IsMatch(part, @"^https?://"))
                {
                    var link = new Hyperlink
                    {
                        NavigateUri = null,
                        UnderlineStyle = UnderlineStyle.Single,
                        Foreground = new SolidColorBrush(isMe
                                        ? Microsoft.UI.Colors.White
                                        : Microsoft.UI.Colors.DodgerBlue),
                    };
                    link.Inlines.Add(new Run { Text = part });
                    link.Click += async (s, e) =>
                    {
                        await Launcher.LaunchUriAsync(new Uri(part));
                    };
                    paragraph.Inlines.Add(link);
                }
                else
                {
                    paragraph.Inlines.Add(new Run { Text = part });
                }
            }

            richText.Blocks.Add(paragraph);
            b.Child = richText;
            MessagesPanel.Children.Add(b);
            ScrollToBottom();
        }
        #endregion

        #region 输入与重连
        private async void SendBtn_Click(object? sender, RoutedEventArgs? e)
        {
            var txt = InputBox.Text.Trim();
            if (string.IsNullOrEmpty(txt) || _ws?.State != WebSocketState.Open) return;

            try
            {
                var payload = JsonSerializer.Serialize(new { type = "user", content = txt });
                if (_cts == null) return;
                await _ws.SendAsync(new ArraySegment<byte>(Encoding.UTF8.GetBytes(payload)),
                                    WebSocketMessageType.Text, true, _cts.Token);
                AddMessage(txt, true);
                InputBox.Text = string.Empty;
            }
            catch (Exception ex)
            {
                AddMessage("发送失败: " + ex.Message, false);
            }
        }

        private void InputBox_KeyDown(object sender, KeyRoutedEventArgs e)
        {
            if (e.Key == Windows.System.VirtualKey.Enter && !string.IsNullOrWhiteSpace(InputBox.Text))
            {
                e.Handled = true;
                SendBtn_Click(null, null);
            }
        }

        private async void ReconnectBtn_Click(object sender, RoutedEventArgs e)
        {
            MessagesPanel.Children.Clear();
            await InitializeWebSocketAsync();
        }
        #endregion

        #region 滚动与清理
        private void ScrollToBottom(bool force = false)
        {
            DispatcherQueue.TryEnqueue(() =>
                ChatScroll.ChangeView(null, ChatScroll.ScrollableHeight, null, !force));
        }

        private void Cleanup()
        {
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;
            _ws?.Dispose();
            _ws = null;
        }
        #endregion
    }
}