using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Xdows_Security
{

    public sealed partial class InterceptWindow : Window
    {

        public static void ShowOrActivate()
        {
            var w = new InterceptWindow();
            try { w.Activate(); } catch { }
        }

        public InterceptWindow()
        {
            InitializeComponent();
            var manager = WinUIEx.WindowManager.Get(this);
            manager.MinWidth = 500;
            manager.MinHeight = 400;
            manager.Width = 700;
            manager.Height = 600;
            //Instance = this;
        }
    }
}
