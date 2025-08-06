using System;
using System.IO;
using System.Linq;
using static Xdows.ScanEngine.ScanEngine;

namespace Xdows.ScanEngine
{
    public static class DllScan
    {
        public static bool Scan(string path, PEInfo info)
        {
            return info.ExportsName?
                .Any(e => e?.IndexOf("Hook", StringComparison.OrdinalIgnoreCase) >= 0 ||
                          e?.IndexOf("Virus", StringComparison.OrdinalIgnoreCase) >= 0 ||
                          e?.IndexOf("Bypass", StringComparison.OrdinalIgnoreCase) >= 0) == true;
        }
    }
}