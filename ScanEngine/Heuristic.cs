using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static Xdows.ScanEngine.ScanEngine;

namespace Xdows.ScanEngine
{
    public static class Heuristic
    {
        public static int Evaluate(string path, PEInfo peInfo, bool deepScan, out string extra)
        {
            extra = string.Empty;
            var score = 0;

            // 读取文件内容
            var fileContent = File.ReadAllBytes(path);

            // 文件扩展名检查
            var fileExtension = Path.GetExtension(path).ToLower();
            if (fileExtension == ".bat" || fileExtension == ".cmd")
            {
                score += IsSuspiciousBat(fileContent) ? 10 : 0;
                extra += " CamouflageBat";
            }
            else if (fileExtension == ".doc" || fileExtension == ".docx")
            {
                score += IsSuspiciousDoc(fileContent) ? 10 : 0;
                extra += " DocVirus";
            }
            // PE 文件特征检查
            if (fileExtension == ".exe" || fileExtension == ".dll")
            {
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "LoadLibrary", "GetProcAddress" }) ? 15 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "SetFileAttributes", "FILE_ATTRIBUTE_HIDDEN" }) ? 20 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "SHFormatDrive" }) ? 20 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "RtlAdjustPrivilege" }) ? 20 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "HideCurrentProcess" }) ? 20 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "SetFilePointer", "WriteFile" }) ? 15 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "CreateService", "StartService" }) ? 15 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "CopyFile", "CreateDirectory", "DeleteFile", "GetFullPathName" }) ? 5 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "CreateObject", "Scriptlet.TypeLib", "Shell.Application", "Scripting.FileSystemObject" }) ? 15 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "GetDlgItemInt", "GetDlgItemText", "GetDlgItemTextA" }) ? 15 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "InternetReadFile", "FtpGetFile", "URLDownloadToFile", "WinExec", "RegCreateKey" }) ? 20 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "CallNextHookEx", "SetWindowsHook" }) ? 20 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "WriteConsole" }) ? 5 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "GetModuleFileName", "GetModuleHandle" }) ? 20 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "WNetAddConnection" }) ? 15 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "CopyScreen" }) ? 15 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "ExitWindows" }) ? 5 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "URLDownloadToFile" }) ? 15 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "URLDownloadToCacheFile" }) ? -15 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "mouse_event", "keydb_event" }) ? 15 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "SetPriorityClass" }) ? 15 : 0;
                score += ContainsSuspiciousApi(peInfo.ImportsName, new[] { "EnumAudioEndpoints" }) ? 15 : 0;
            }

            // 深度扫描
            if (deepScan)
            {
                score += ContainsSuspiciousContent(fileContent, new[] { ".sys" }) ? 10 : 0;
                score += ContainsSuspiciousContent(fileContent, new[] { "Virtual" }) ? 20 : 0;
                score += ContainsSuspiciousContent(fileContent, new[] { "BlackMoon" }) ? 15 : 0;
                score += ContainsSuspiciousContent(fileContent, new[] { "PYAS", "wsctrlsvc", "ESET", "zhudongfangyu", "avp", "avconsol", "ASWSCAN", "KWatch", "QQPCTray" }) ? 20 : 0;
                score += ContainsSuspiciousContent(fileContent, new[] { "DelegateExecute", "fodhelper.exe" }) ? 20 : 0;
                score += ContainsSuspiciousContent(fileContent, new[] { "sandboxie", "vmware - tray", "Detonate", "Vmware", "VMWARE", "Sandbox", "SANDBOX" }) ? 20 : 0;
            }

            return score >= 50 ? score : 0;
        }

        private static bool IsSuspiciousBat(byte[] fileContent)
        {
            var content = Encoding.UTF8.GetString(fileContent);
            return content.Contains("program cannot be run in") ||
                   content.Contains("LoadLibraryA") ||
                   content.Contains("Win32") ||
                   content.Contains("kernel32.dll") ||
                   content.Contains("ntdll.dll") ||
                   content.Contains("GetProcAddress") ||
                   content.Contains("C:\\windows\\") ||
                   content.Contains("*.exe") ||
                   content.Contains("Shutdown");
        }

        private static bool IsSuspiciousDoc(byte[] fileContent)
        {
            var content = Encoding.UTF8.GetString(fileContent);
            return content.Contains("This program cannot be run") ||
                   content.Contains("LoadLibraryA") ||
                   content.Contains("RichN") ||
                   content.Contains("kernel32.dll") ||
                   content.Contains("Win32") ||
                   content.Contains("GetProcAddress") ||
                   content.Contains("邢") && content.Contains("唷") &&
                   (content.Contains("Microsoft Office Word") || content.Contains("Microsoft Word"));
        }

        private static bool ContainsSuspiciousApi(string[] apis, string[] keywords)
        {
            if (apis == null) {
                return false;
            }
            return keywords.Any(keyword => apis.Any(api => api.Contains(keyword)));
        }

        private static bool ContainsSuspiciousContent(byte[] fileContent, string[] keywords)
        {
            var content = Encoding.UTF8.GetString(fileContent);
            return keywords.Any(keyword => content.Contains(keyword));
        }
    }
}