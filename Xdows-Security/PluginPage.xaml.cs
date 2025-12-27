using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using PluginSystem;

namespace Xdows_Security
{
    public sealed partial class PluginPage : Page
    {
        private readonly PSystem _pSystem = new();
        ObservableCollection<PluginItem> PluginItems { get; } = new();

        public PluginPage()
        {
            InitializeComponent();
            PluginGridView.ItemsSource = PluginItems;
            Loaded += OnLoaded;
        }

        private void OnLoaded(object? sender, RoutedEventArgs e)
        {
            LoadPlugins();
        }

        private void LoadPlugins()
        {
            PluginItems.Clear();
           
            _pSystem.LoadPlugin("Test");
            var plugins = _pSystem.GetPlugins() ?? new System.Collections.Generic.List<PSystem.Plugin>();
            foreach (var p in plugins)
            {
                PluginItems.Add(new PluginItem
                {
                    Name = p.Name ?? "Unknown",
                    Description = p.Config?.Description ?? "未提供描述",
                    ShortName = (p.Name?.Length > 2) ? p.Name.Substring(0, 2).ToUpperInvariant() : (p.Name ?? "PL"),
                    SourcePlugin = p
                });
            }
        }

        private async void OpenButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is PluginItem item && item.SourcePlugin?.PluginPage != null)
            {
                var dialog = new ContentDialog
                {
                    Title = item.Name,
                    XamlRoot = this.XamlRoot,
                    PrimaryButtonText = "关闭",
                    Content = item.SourcePlugin.PluginPage,
                    DefaultButton = ContentDialogButton.Primary
                };

                try
                {
                    await dialog.ShowAsync();
                }
                catch (Exception ex)
                {
                    var err = new ContentDialog
                    {
                        Title = "打开插件失败",
                        XamlRoot = this.XamlRoot,
                        Content = ex.Message,
                        PrimaryButtonText = "确定"
                    };
                    await err.ShowAsync();
                }
            }
        }

        private async void UnloadButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is PluginItem item)
            {
                var confirm = new ContentDialog
                {
                    Title = "确认卸载",
                    Content = $"确认要卸载插件 \"{item.Name}\" 吗？",
                    PrimaryButtonText = "卸载",
                    CloseButtonText = "取消",
                    XamlRoot = this.XamlRoot
                };

                var result = await confirm.ShowAsync();
                if (result == ContentDialogResult.Primary)
                {
                    try
                    {
                        _pSystem.UnloadPlugin(item.Name);
                    }
                    catch
                    {
                        // 忽略卸载异常，保证 UI 更新
                    }

                    PluginItems.Remove(item);
                }
            }
        }

        private class PluginItem
        {
            public string Name { get; set; } = string.Empty;
            public string Description { get; set; } = string.Empty;
            public string ShortName { get; set; } = string.Empty;
            public PSystem.Plugin? SourcePlugin { get; set; }
        }
    }
}
