using static ScanEngine.ScanEngine;

namespace ScanEngine
{
    public static class DllScan
    {
        public static bool Scan(PEInfo info)
        {
            if (info.ExportsName?
                .Any(e => e?.IndexOf("Py", StringComparison.OrdinalIgnoreCase) >= 0 ||
                          e?.IndexOf("Scan", StringComparison.OrdinalIgnoreCase) >= 0 ||
                          e?.IndexOf("chromium", StringComparison.OrdinalIgnoreCase) >= 0 ||
                          e?.IndexOf("blink", StringComparison.OrdinalIgnoreCase) >= 0 ||
                          e?.IndexOf("Qt", StringComparison.OrdinalIgnoreCase) >= 0) == true)
            {
                return false;
            }
            return info.ExportsName?
                .Any(e => e?.IndexOf("Hook", StringComparison.OrdinalIgnoreCase) >= 0 ||
                          e?.IndexOf("Virus", StringComparison.OrdinalIgnoreCase) >= 0 ||
                          e?.IndexOf("Bypass", StringComparison.OrdinalIgnoreCase) >= 0) == true;
        }
    }
}