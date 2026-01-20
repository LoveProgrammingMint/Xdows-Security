using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Windows.Storage;

namespace Xdows_Security
{
    public static class TCPMessageProtocol
    {
        private static readonly JsonSerializerOptions CachedJsonOptions = new()
        {
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
        public static byte[] EncodeMessage(Dictionary<string, object> message)
        {
            string jsonStr = JsonSerializer.Serialize(message, options: CachedJsonOptions);

            byte[] messageBytes = Encoding.UTF8.GetBytes(jsonStr);

            byte[] lengthPrefix = BitConverter.GetBytes(messageBytes.Length);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(lengthPrefix); // 转换为网络字节序（大端序）
            }
            byte[] result = new byte[4 + messageBytes.Length];
            global::System.Buffer.BlockCopy(lengthPrefix, 0, result, 0, 4);
            global::System.Buffer.BlockCopy(messageBytes, 0, result, 4, messageBytes.Length);

            return result;
        }
        public static async Task<Dictionary<string, object>?> DecodeMessageAsync(Stream stream)
        {
            try
            {
                byte[] lengthData = new byte[4];
                int totalBytesRead = 0;
                while (totalBytesRead < 4)
                {
                    int read = await stream.ReadAsync(lengthData.AsMemory(totalBytesRead, 4 - totalBytesRead));
                    if (read == 0)
                    {
                        return null;
                    }
                    totalBytesRead += read;
                }

                if (totalBytesRead != 4)
                {
                    return null;
                }

                byte[] networkOrderBytes = (byte[])lengthData.Clone();
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(networkOrderBytes);
                }
                int messageLength = BitConverter.ToInt32(networkOrderBytes, 0);

                if (messageLength <= 0 || messageLength > 10 * 1024 * 1024)
                {
                    return null;
                }

                byte[] messageData = new byte[messageLength];
                totalBytesRead = 0;
                while (totalBytesRead < messageLength)
                {
                    int read = await stream.ReadAsync(messageData.AsMemory(totalBytesRead, messageLength - totalBytesRead));
                    if (read == 0)
                    {
                        return null;
                    }
                    totalBytesRead += read;
                }
                if (totalBytesRead != messageLength)
                {
                    return null;
                }
                string jsonStr = Encoding.UTF8.GetString(messageData);
                return JsonSerializer.Deserialize<Dictionary<string, object>>(jsonStr, CachedJsonOptions);
            }
            catch (Exception)
            {
                return null;
            }
        }
    }

    /// <summary>
    /// 反馈频道TCP客户端
    /// </summary>
    public class FeedbackTCPClient
    {
        private TcpClient? _tcpClient;
        private NetworkStream? _stream;
        private CancellationTokenSource? _cts;
        private Task? _receiveTask;
        private Task? _heartbeatTask;
        private bool _isConnected = false;
        private string _username = "";
        private string _serverHost = "103.118.245.82";
        private int _serverPort = 8888;
        // 事件
        public event EventHandler<string>? OnConnected;
        public event EventHandler<string>? OnDisconnected;
        public event EventHandler<Dictionary<string, object>>? OnMessageReceived;
        public event EventHandler<string>? OnError;
        public event EventHandler<FileDownloadCompletedEventArgs>? OnFileDownloadCompleted;
        public FeedbackTCPClient()
        {
            LoadSettings();
        }
        private async void LoadSettings()
        {
            try
            {
                // 尝试从本地存储加载设置
                ApplicationDataContainer localSettings = ApplicationData.Current.LocalSettings;

                if (localSettings.Values.TryGetValue("FeedbackUsername", out var usernameObj) &&
                    usernameObj is string username)
                {
                    _username = username;
                }

                if (localSettings.Values.TryGetValue("FeedbackServerHost", out var hostObj) &&
                    hostObj is string host)
                {
                    _serverHost = host;
                }

                if (localSettings.Values.TryGetValue("FeedbackServerPort", out var portObj) &&
                    portObj is string portStr && int.TryParse(portStr, out int port))
                {
                    _serverPort = port;
                }

                // 如果没有用户名，生成一个默认的
                if (string.IsNullOrEmpty(_username))
                {
                    _username = Environment.MachineName + "_" + Environment.UserName;
                    await SaveSettingsAsync();
                }
            }
            catch (Exception ex)
            {
                OnError?.Invoke(this, $"加载设置失败: {ex.Message}");
            }
        }
        private async Task SaveSettingsAsync()
        {
            try
            {
                ApplicationDataContainer localSettings = ApplicationData.Current.LocalSettings;
                localSettings.Values["FeedbackUsername"] = _username;
                localSettings.Values["FeedbackServerHost"] = _serverHost;
                localSettings.Values["FeedbackServerPort"] = _serverPort.ToString();

                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                OnError?.Invoke(this, $"保存设置失败: {ex.Message}");
            }
        }
        public async Task SetUsernameAsync(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                throw new ArgumentException("用户名不能为空");

            _username = username.Trim();
            await SaveSettingsAsync();
        }
        public async Task SetServerAsync(string host, int port)
        {
            if (string.IsNullOrWhiteSpace(host))
                throw new ArgumentException("服务器地址不能为空");

            if (port <= 0 || port > 65535)
                throw new ArgumentException("端口必须在1-65535范围内");

            _serverHost = host.Trim();
            _serverPort = port;
            await SaveSettingsAsync();
        }
        public async Task<bool> ConnectAsync()
        {
            if (_isConnected)
                return true;

            try
            {
                Cleanup();

                _cts = new CancellationTokenSource();
                _tcpClient = new TcpClient();

                // 连接到服务器
                await _tcpClient.ConnectAsync(_serverHost, _serverPort);
                _stream = _tcpClient.GetStream();

                // 等待一小段时间确保连接完全建立
                await Task.Delay(100);

                // 检查连接是否仍然有效
                if (!_tcpClient.Connected || _stream == null)
                {
                    OnError?.Invoke(this, "连接建立失败");
                    Cleanup();
                    return false;
                }

                // 发送注册消息
                var registerMessage = new Dictionary<string, object>
                {
                    ["type"] = "register",
                    ["username"] = _username
                };

                // 先启动接收任务，确保能接收到服务器的响应
                _receiveTask = Task.Run(ReceiveLoopAsync);

                await SendMessageAsync(registerMessage);

                // 接收注册响应，设置超时
                var responseTask = TCPMessageProtocol.DecodeMessageAsync(_stream);
                var timeoutTask = Task.Delay(10000); // 10秒超时

                var completedTask = await Task.WhenAny(responseTask, timeoutTask);

                if (completedTask == timeoutTask)
                {
                    OnError?.Invoke(this, "等待服务器响应超时");
                    Cleanup();
                    return false;
                }

                var response = await responseTask;
                if (response != null &&
                    response.TryGetValue("type", out var typeObj) &&
                    typeObj.ToString() == "register_success")
                {
                    _isConnected = true;

                    // 启动心跳任务
                    _heartbeatTask = Task.Run(HeartbeatLoopAsync);

                    // 触发OnConnected事件
                    OnConnected?.Invoke(this, $"已连接到服务器 {_serverHost}:{_serverPort}");

                    // 触发OnMessageReceived事件处理register_success消息
                    OnMessageReceived?.Invoke(this, response);

                    return true;
                }
                else
                {
                    string errorMsg = "服务器拒绝了连接请求";
                    if (response != null)
                    {
                        if (response.TryGetValue("message", out var msgObj))
                        {
                            errorMsg = msgObj.ToString() ?? errorMsg;
                        }
                        else if (response.TryGetValue("type", out var typeObj2))
                        {
                            errorMsg = $"服务器返回了意外的响应类型: {typeObj2}";
                        }
                    }
                    else
                    {
                        errorMsg = "服务器没有返回有效的响应";
                    }

                    OnError?.Invoke(this, errorMsg);
                    Cleanup();
                    return false;
                }
            }
            catch (Exception ex)
            {
                OnError?.Invoke(this, $"连接失败: {ex.Message}");
                Cleanup();
                return false;
            }
        }
        public async Task DisconnectAsync()
        {
            if (!_isConnected)
                return;

            try
            {
                // Cleanup will handle setting _isConnected to false
                Cleanup();

                OnDisconnected?.Invoke(this, "已断开连接");
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                OnError?.Invoke(this, $"断开连接时出错: {ex.Message}");
            }
        }
        public async Task SendMessageAsync(string message)
        {
            if (!_isConnected || _stream == null)
                throw new InvalidOperationException("未连接到服务器");

            if (string.IsNullOrWhiteSpace(message))
                return;

            var messageDict = new Dictionary<string, object>
            {
                ["type"] = "message",
                ["content"] = message.Trim()
            };

            await SendMessageAsync(messageDict);
        }
        public async Task SendFileAsync(string fileName, byte[] fileBytes)
        {
            if (!_isConnected || _stream == null)
                throw new InvalidOperationException("未连接到服务器");

            if (string.IsNullOrWhiteSpace(fileName))
                throw new ArgumentException("文件名不能为空");

            if (fileBytes == null || fileBytes.Length == 0)
                throw new ArgumentException("文件内容不能为空");

            // 转换为Base64
            string base64 = Convert.ToBase64String(fileBytes);

            var fileMessage = new Dictionary<string, object>
            {
                ["type"] = "file",
                ["name"] = fileName,
                ["size"] = fileBytes.Length,
                ["content"] = base64
            };

            await SendMessageAsync(fileMessage);
        }
        public async Task DownloadFileAsync(string fileId, string downloadUrl, string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileId))
                throw new ArgumentException("文件ID不能为空");

            if (string.IsNullOrWhiteSpace(downloadUrl))
                throw new ArgumentException("下载URL不能为空");

            if (string.IsNullOrWhiteSpace(fileName))
                throw new ArgumentException("文件名不能为空");

            // 直接从URL下载文件
            using var httpClient = new HttpClient();
            System.Diagnostics.Debug.WriteLine($"开始HTTP请求: {downloadUrl}");

            using var response = await httpClient.GetAsync(downloadUrl);
            System.Diagnostics.Debug.WriteLine($"HTTP响应状态: {response.StatusCode}");

            response.EnsureSuccessStatusCode();

            // 获取文件内容
            byte[] fileBytes = await response.Content.ReadAsByteArrayAsync();
            System.Diagnostics.Debug.WriteLine($"下载完成，文件大小: {fileBytes.Length} 字节");

            // 保存文件到下载目录
            string downloadsFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Downloads");
            Directory.CreateDirectory(downloadsFolder);
            string filePath = Path.Combine(downloadsFolder, fileName);

            System.Diagnostics.Debug.WriteLine($"保存文件到: {filePath}");
            File.WriteAllBytes(filePath, fileBytes);

            System.Diagnostics.Debug.WriteLine($"文件已保存到: {filePath}");

            // 触发下载完成事件
            OnFileDownloadCompleted?.Invoke(this, new FileDownloadCompletedEventArgs(fileId, fileName, filePath));
        }
        public async Task MarkMessageReadAsync(string messageId)
        {
            if (!_isConnected || _stream == null)
                throw new InvalidOperationException("未连接到服务器");

            if (string.IsNullOrWhiteSpace(messageId))
                return;

            var readMessage = new Dictionary<string, object>
            {
                ["type"] = "mark_read",
                ["message_id"] = messageId
            };

            await SendMessageAsync(readMessage);
        }
        private async Task SendMessageAsync(Dictionary<string, object> message)
        {
            if (_stream == null)
                return;

            // 在连接过程中允许发送注册消息
            if (!_isConnected && message["type"]?.ToString() != "register")
                return;

            try
            {
                byte[] messageBytes = TCPMessageProtocol.EncodeMessage(message);

                // 使用锁确保线程安全
                lock (_stream)
                {
                    _stream.Write(messageBytes, 0, messageBytes.Length);
                    _stream.Flush();
                }
            }
            catch (Exception ex)
            {
                // 连接可能已断开，更新状态
                _isConnected = false;
                OnError?.Invoke(this, $"发送消息失败: {ex.Message}");
                OnDisconnected?.Invoke(this, "连接已断开");
            }
        }
        private async Task HeartbeatLoopAsync()
        {
            if (_cts == null)
                return;

            try
            {
                while (!_cts.Token.IsCancellationRequested && _isConnected)
                {
                    // 每30秒发送一次心跳
                    await Task.Delay(30000, _cts.Token);

                    if (_isConnected && !_cts.Token.IsCancellationRequested)
                    {
                        var pingMessage = new Dictionary<string, object>
                        {
                            ["type"] = "ping"
                        };

                        await SendMessageAsync(pingMessage);
                    }
                }
            }
            catch (TaskCanceledException)
            {
                // 任务被取消，正常退出
            }
            catch (Exception ex)
            {
                OnError?.Invoke(this, $"心跳出错: {ex.Message}");
            }
        }
        private async Task ReceiveLoopAsync()
        {
            if (_stream == null || _cts == null)
                return;

            try
            {
                while (!_cts.Token.IsCancellationRequested && _isConnected)
                {
                    var message = await TCPMessageProtocol.DecodeMessageAsync(_stream);
                    if (message == null)
                    {
                        // 连接已关闭
                        break;
                    }

                    // 记录接收到的消息
                    System.Diagnostics.Debug.WriteLine($"客户端接收到消息: {System.Text.Json.JsonSerializer.Serialize(message)}");

                    // 处理心跳包
                    if (message.TryGetValue("type", out var typeObj) && typeObj.ToString() == "pong")
                    {
                        continue;
                    }

                    // 触发消息接收事件
                    OnMessageReceived?.Invoke(this, message);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"接收消息循环出错: {ex.Message}");
                OnError?.Invoke(this, $"接收消息时出错: {ex.Message}");
            }
            finally
            {
                // 如果循环结束，说明连接已断开
                if (_isConnected)
                {
                    _isConnected = false;
                    OnDisconnected?.Invoke(this, "连接已断开");
                }
            }
        }
        private void Cleanup()
        {
            _isConnected = false;

            try
            {
                _cts?.Cancel();

                _stream?.Close();
                _stream?.Dispose();
                _tcpClient?.Close();
                _tcpClient?.Dispose();
            }
            catch { }
            _stream = null;
            _tcpClient = null;
            _cts = null;
            try
            {
                _receiveTask?.Wait(1000);
                _heartbeatTask?.Wait(1000);

            }
            catch { }
            _receiveTask = null;
            _heartbeatTask = null;
        }
        public bool IsConnected => _isConnected;
        public string Username => _username;
        public string ServerHost => _serverHost;
        public int ServerPort => _serverPort;
    }
    public class FileDownloadCompletedEventArgs(string fileId, string fileName, string filePath) : EventArgs
    {
        public string FileId { get; } = fileId;
        public string FileName { get; } = fileName;
        public string FilePath { get; } = filePath;
    }
}