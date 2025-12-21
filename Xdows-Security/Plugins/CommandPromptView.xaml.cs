using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace Xdows_Security.Views
{
    public sealed partial class CommandPromptView : UserControl
    {
        private readonly StringBuilder _cmdOutputSb = new();
        private Process? _cmdProcess;
        private bool _cmdRunning;

        public CommandPromptView()
        {
            this.InitializeComponent();
        }

        private async void ExecuteButton_Click(object sender, RoutedEventArgs e)
        {
            var cmd = CmdInput.Text.Trim();
            if (string.IsNullOrWhiteSpace(cmd) || (_cmdRunning == false && _cmdProcess?.HasExited == false)) return;

            if (_cmdProcess == null || _cmdProcess.HasExited)
            {
                _cmdOutputSb.Clear();
                CmdOutput.Text = "命令提示符启动成功，请输入相关命令。";
                StartCmd();
            }
            try
            {
                await _cmdProcess!.StandardInput.WriteLineAsync(cmd);
            }
            catch { }
            CmdInput.Text = string.Empty;
        }

        private void StartCmd()
        {
            if (_cmdProcess != null && !_cmdProcess.HasExited) return;

            _cmdProcess = new Process
            {
                StartInfo = new ProcessStartInfo
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

        private void OnOutput(object? _, DataReceivedEventArgs e)
        {
            if (e.Data != null) AppendOutput(e.Data);
        }

        private void AppendOutput(string text)
        {
            _ = DispatcherQueue.TryEnqueue(() =>
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
}
