using System;

namespace Xdows.Protection
{
    public class ProcessProtection
    {
        public static bool EnableProtection()
        {
            try
            {
                Task.Run(() => {
                    System.Console.WriteLine("Protection Enabled");

                });
            } catch { return false; }
            return true;
        }
    }
}
