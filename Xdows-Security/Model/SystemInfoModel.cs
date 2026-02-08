using System.Runtime.InteropServices;
namespace Xdows_Security.Model
{
    public class SystemInfoModel
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORYSTATUSEX
        {
            public uint dwLength, dwMemoryLoad;
            public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile,
                         ullAvailPageFile, ullTotalVirtual, ullAvailVirtual,
                         ullAvailExtendedVirtual;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        public (bool ok, uint load, string display) GetMemory()
        {
            var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
            if (!GlobalMemoryStatusEx(ref mem)) return (false, 0, "");
            double t = mem.ullTotalPhys, a = mem.ullAvailPhys, u = t - a;
            string[] units = ["B", "KB", "MB", "GB"];
            int idx = 0;
            while (t >= 1024 && idx < units.Length - 1) { t /= 1024; a /= 1024; u /= 1024; idx++; }
            return (true, mem.dwMemoryLoad, $"{u:F1} {units[idx]} / {t:F1} {units[idx]} ({mem.dwMemoryLoad}%)");
        }

        public string OSName => App.OsName;
        public string OSVersion => App.OsVersion;
    }
}