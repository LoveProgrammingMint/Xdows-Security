using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.IO;
using TrustQuarantine;
using WinUI3Localizer;

namespace Xdows_Security
{
    public sealed partial class InterceptWindow : Window
    {
        private readonly string? _originalFilePath;
        private readonly string? _type;

        private static readonly System.Collections.Generic.Dictionary<string, InterceptWindow> _openWindows = [];

        public static void ShowOrActivate(bool isSucceed, string path, string type)
        {
            string key = $"{path}|{type}";
            if (_openWindows.TryGetValue(key, out var existingWindow))
            {
                try
                {
                    existingWindow.Activate();
                    return;
                }
                catch
                {
                    _openWindows.Remove(key);
                }
            }
            var w = new InterceptWindow(isSucceed, path, type, key);
            w.Activate();
        }

        private InterceptWindow(bool isSucceed, string path, string type, string key)
        {
            this.InitializeComponent();
            var manager = WinUIEx.WindowManager.Get(this);
            manager.MinWidth = 350;
            manager.MinHeight = 330;
            manager.Width = 400;
            manager.Height = 470;
            manager.IsMaximizable = false;
            manager.IsMinimizable = true;
            manager.IsResizable = false;
            manager.IsTitleBarVisible = false;
            this.SystemBackdrop = new Microsoft.UI.Xaml.Media.MicaBackdrop();
            _originalFilePath = path;
            _openWindows[key] = this;
            try
            {
                Localizer.Get().LanguageChanged += Localizer_LanguageChanged;
                UpdateWindowTitle();
            }
            catch { }
            this.Closed += (sender, e) =>
            {
                Localizer.Get().LanguageChanged -= Localizer_LanguageChanged;
                _openWindows.Remove(key);
            };
            _type = type;
            UpdateWindowTitle();
            InitializeUI(path);
            PositionWindowAtBottomRight();
        }

        private void PositionWindowAtBottomRight()
        {
            try
            {
                var displayArea = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(this.AppWindow.Id, Microsoft.UI.Windowing.DisplayAreaFallback.Nearest);
                if (displayArea != null)
                {
                    var workArea = displayArea.WorkArea;
                    var windowWidth = (int)this.AppWindow.Size.Width;
                    var windowHeight = (int)this.AppWindow.Size.Height;
                    var x = workArea.Width - windowWidth - 20;
                    var y = workArea.Height - windowHeight - 20;
                    this.AppWindow.Move(new Windows.Graphics.PointInt32(x, y));
                }
            }
            catch { }
        }

        private void Localizer_LanguageChanged(object? sender, WinUI3Localizer.LanguageChangedEventArgs e)
        {
            DispatcherQueue.TryEnqueue(() => UpdateWindowTitle());
        }

        private void UpdateWindowTitle()
        {
            try
            {
                var title = Localizer.Get().GetLocalizedString("InterceptWindow_WindowTitle");
                if (!string.IsNullOrEmpty(title))
                    this.Title = title;
            }
            catch { }
        }

        private void InitializeUI(string path)
        {
            ProgramNameText.Text = Path.GetFileName(path);
            FilePathText.Text = path;
            ThreatTitleText.Text = "检测到安全威胁";
            ThreatSubtitleText.Text = "已拦截可疑程序，请立即处理";
            ThreatTypeText.Text = _type == "Reg" ? "注册表修改" : "木马程序";
            ThreatLevelText.Text = "高危";
            DetectionTimeText.Text = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            SecurityAdviceText.Text = "建议立即隔离该文件，防止恶意程序继续运行";
        }

        private async void TrustButton_Click(object sender, RoutedEventArgs e)
        {
            await AddToTrust();
        }

        private async void ConfirmButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private async System.Threading.Tasks.Task AddToTrust()
        {
            try
            {
                if (string.IsNullOrWhiteSpace(_originalFilePath))
                {
                    await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Message"));
                    return;
                }
                var quarantineItems = QuarantineManager.GetQuarantineItems();
                var qi = quarantineItems.Find(q => string.Equals(q.SourcePath, _originalFilePath, StringComparison.OrdinalIgnoreCase));
                if (qi != null)
                {
                    bool added = await TrustManager.AddToTrustByHash(_originalFilePath, qi.FileHash);
                    if (!added)
                    {
                        await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Message"));
                        return;
                    }
                    bool restored = await QuarantineManager.RestoreFile(qi.FileHash);
                    if (restored)
                    {
                        await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Success_Title"), string.Format(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Success_Message"), _originalFilePath));
                        this.Close();
                        return;
                    }
                    await TrustManager.RemoveFromTrust(_originalFilePath);
                    await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Message"));
                    return;
                }

                if (File.Exists(_originalFilePath))
                {
                    bool success = await TrustManager.AddToTrust(_originalFilePath);
                    if (success)
                    {
                        await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Success_Title"), string.Format(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Success_Message"), _originalFilePath));
                        this.Close();
                        return;
                    }
                    else
                    {
                        await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Message"));
                        return;
                    }
                }

                await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Message"));
            }
            catch (Exception ex)
            {
                await ShowMessageDialog(Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Title"), Localizer.Get().GetLocalizedString("InterceptWindow_Trust_Failed_Message"));
                LogText.AddNewLog(LogLevel.ERROR, "InterceptWindow - AddToTrust - Failed", ex.ToString());
            }
        }

        private async System.Threading.Tasks.Task ShowMessageDialog(string title, string message)
        {
            ContentDialog dialog = new()
            {
                Title = title,
                Content = message,
                PrimaryButtonText = Localizer.Get().GetLocalizedString("Button_Confirm"),
                PrimaryButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"],
                XamlRoot = this.Content.XamlRoot
            };

            await dialog.ShowAsync();
        }
    }
}
