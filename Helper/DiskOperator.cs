using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace Helper
{
    public static class DiskOperator
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern SafeFileHandle CreateFile(
    string lpFileName,
    uint dwDesiredAccess,
    uint dwShareMode,
    IntPtr lpSecurityAttributes,
    uint dwCreationDisposition,
    uint dwFlagsAndAttributes,
    IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(
            SafeFileHandle hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;

        public static byte[] ReadBootSector(int physicalDriveIndex)
        {
            string devicePath = $"\\\\.\\PhysicalDrive{physicalDriveIndex}";
            return ReadSector(devicePath, 512) ?? [];
        }
        public static byte[] ReadVolumeBootRecord(string driveLetter)
        {
            if (string.IsNullOrWhiteSpace(driveLetter))
                return [];
            string devicePath = $"\\\\.\\{driveLetter.TrimEnd(':').ToUpper()}:";
            return ReadSector(devicePath, 512) ?? [];
        }

        private static byte[]? ReadSector(string devicePath, int sectorSize)
        {
            SafeFileHandle handle = CreateFile(
                devicePath,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero);

            if (handle.IsInvalid)
            {
                return null;
            }

            try
            {
                byte[] buffer = new byte[sectorSize];
                if (ReadFile(handle, buffer, (uint)sectorSize, out uint bytesRead, IntPtr.Zero))
                {
                    if (bytesRead == sectorSize)
                        return buffer;
                }
                return null;
            }
            finally
            {
                handle?.Dispose();
            }
        }
    }
}
