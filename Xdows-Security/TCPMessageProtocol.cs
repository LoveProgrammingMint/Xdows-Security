using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Xdows_Security
{
    public static class TCPMessageProtocol
    {
        public static byte[] EncodeMessage(Dictionary<string, object> message)
        {
            string jsonStr = JsonSerializer.Serialize(message, JsonContext.Default.DictionaryStringObject);

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
                return JsonSerializer.Deserialize(jsonStr, JsonContext.Default.DictionaryStringObject);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"解码消息异常: {ex.Message}");
                // 重新抛出异常，让调用方处理
                throw;
            }
        }
    }
}
