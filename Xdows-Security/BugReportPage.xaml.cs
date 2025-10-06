using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using System;
using System.IO;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Xdows_Security
{
    public sealed partial class BugReportPage : Page
    {
        private ClientWebSocket _ws;
        private CancellationTokenSource _cts;

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
                StatusTxt.Text = "已连接";
                _ = Task.Run(() => ReceiveLoopAsync(_cts.Token));
            }
            catch (Exception ex)
            {
                StatusTxt.Text = "连接失败";
                AddMessage("连接失败: " + ex.Message, false);
            }
        }

        private async Task ReceiveLoopAsync(CancellationToken token)
        {
            await using var ms = new MemoryStream();
            var buffer = new ArraySegment<byte>(new byte[4 * 1024]);
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
                            ExtractAndAddHistory(json,
                                                (msg, isMe) => AddMessage(msg, isMe),
                                                () => ScrollToBottom(force: true)));
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

        private void ExtractAndAddHistory(string json,
                                                 Action<string, bool> add,
                                                 Action scrollToBottom)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.TryGetProperty("total_messages", out var v))
                    return;
                bool isHistory = root.TryGetProperty("type", out var t) &&
                                 t.ValueKind == JsonValueKind.String &&
                                 t.GetString().Equals("history", StringComparison.OrdinalIgnoreCase);

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
                        if (item.TryGetProperty("content", out var inner))
                            add(inner.ToString(), false);
                        else
                            add(item.ToString(), false);

                        if (++count == total)
                            ScrollToBottom(force: true);
                    }
                }
                else
                {
                    add(json, false);
                    ScrollToBottom(force: true);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[HistoryParseError] {ex.Message}\nRaw: {json}");
                add(json, false);
                ScrollToBottom(force: true);
            }
        }
        #endregion

        #region UI 事件
        private async void SendBtn_Click(object sender, RoutedEventArgs e)
        {
            var txt = InputBox.Text.Trim();
            if (string.IsNullOrEmpty(txt) || _ws?.State != WebSocketState.Open) return;

            try
            {
                var payload = JsonSerializer.Serialize(new { type = "user", content = txt });
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

        #region 消息处理
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
            b.Child = new TextBlock
            {
                Text = text,
                TextWrapping = TextWrapping.Wrap,
                IsTextSelectionEnabled = true,
                Foreground = isMe
                    ? new SolidColorBrush(Microsoft.UI.Colors.White)
                    : (Brush)Application.Current.Resources["TextFillColorPrimaryBrush"]
            };
            MessagesPanel.Children.Add(b);

            // 普通消息实时滚动
            ScrollToBottom();
        }

        /// <summary>
        /// 滚动到底部。force=true 时强制立即执行，解决历史消息加载后未滚动问题。
        /// </summary>
        private void ScrollToBottom(bool force = false)
        {
            DispatcherQueue.TryEnqueue(() =>
                ChatScroll.ChangeView(null, ChatScroll.ScrollableHeight, null, !force));
        }
        #endregion

        #region 清理
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