namespace Xdows_Local
{
    public class RegistryScan
    {
        private readonly string[] SuspiciousKeys =
        [
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppInit_DLLs",

            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "SOFTWARE\\Policies\\Microsoft\\Windows\\System",
            "SOFTWARE\\Policies\\Microsoft\\MMC",
            "SOFTWARE\\Classes",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
            "SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies",
            "Software\\Classes\\ms-settings\\Shell\\Open\\command" // fodhelper.exe 提权漏洞
        ];
        public string Scan(string Key)
        {
            if (string.IsNullOrWhiteSpace(Key))
                return string.Empty;

            for (int i = 0; i < SuspiciousKeys.Length; i++)
            {
                if (Key.Contains(SuspiciousKeys[i], StringComparison.OrdinalIgnoreCase))
                {
                    return "Xdows.Local.RegistryScan";
                }
            }
            return string.Empty;
        }
    }
}
