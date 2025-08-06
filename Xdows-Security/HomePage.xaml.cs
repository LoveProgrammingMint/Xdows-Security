using Microsoft.UI.Xaml.Controls;
using System;

namespace Xdows_Security
{
    public sealed partial class HomePage : Page
    {
        public HomePage()
        {
            this.InitializeComponent();
            this.LogTextBox.Text = LogText.Text;
            LogText.TextChanged += LogText_TextChanged;
        }

        private void LogText_TextChanged(object? sender, EventArgs e)
        {

                this.LogTextBox.Text = LogText.Text;
        }
    }
}