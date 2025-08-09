using Microsoft.UI.Xaml.Controls;
using System;
using Windows.ApplicationModel.Resources;//多语言调用

namespace Xdows_Security
{
    public sealed partial class HomePage : Page
    {
        private readonly ResourceLoader _resourceLoader = ResourceLoader.GetForViewIndependentUse(); //多语言调用
        public HomePage()
        {
            this.InitializeComponent();
            LogText.TextChanged += LogText_TextChanged;
            UpdateData();
        }

        private void LogText_TextChanged(object? sender, EventArgs e)
        {
            UpdateData();
        }
        private void UpdateData() {
            this.LogTextBox.Text = LogText.Text;
            if (Protection.IsOpen())
            {
                HomePage_TextBlock.Text = _resourceLoader.GetString("HomePage_TextBlock_Open");
                Icon.Glyph = "\uE73E";
            }
            else
            {
                HomePage_TextBlock.Text = _resourceLoader.GetString("HomePage_TextBlock_Close");
                Icon.Glyph = "\uE711";
            }
        }
    }
}