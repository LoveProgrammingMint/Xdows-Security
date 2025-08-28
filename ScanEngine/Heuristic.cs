using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
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
            if (peInfo.ImportsName == null)
            {
                return score;
            }
            var fileContent = File.ReadAllBytes(path);

            var fileExtension = Path.GetExtension(path).ToLower();

            var suspiciousData = new List<string>();

            if (fileExtension == ".bat" || fileExtension == ".cmd")
            {
                if (IsSuspiciousBat(fileContent))
                {
                    score += 10;
                    suspiciousData.Add("CamouflageBat");
                }
            }
            else if (fileExtension == ".doc" || fileExtension == ".docx")
            {
                if (IsSuspiciousDoc(fileContent))
                {
                    score += 10;
                    suspiciousData.Add("DocVirus");
                }
            }

            if (fileExtension == ".exe" || fileExtension == ".dll")
            {
                if (IsFileDigitallySignedAndValid(path))
                {
                    score -= 5;
                }
                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "LoadLibrary" }))
                {
                    if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "GetProcAddress" }))
                    {
                        score += 15;
                    }
                    else
                    {
                        score += 10;
                    }
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "SetFileAttributes" }) && ContainsSuspiciousApi(peInfo.ImportsName, new[] { "FILE_ATTRIBUTE_HIDDEN" }))
                {
                    score += 20;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "SHFormatDrive" }))
                {
                    score += 20;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "RtlAdjustPrivilege" }))
                {
                    score += 20;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "HideCurrentProcess" }))
                {
                    score += 20;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "SetFilePointer" }))
                {
                    score += 15;
                    if (deepScan && ContainsSuspiciousApi(peInfo.ImportsName, new[] { "WriteFile" }) && ContainsSuspiciousContent(fileContent, new[] { "physicaldrive0" }))
                    {
                        score += 5;
                        suspiciousData.Add("ChangeMBR");
                    }
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "CreateService" }) && ContainsSuspiciousApi(peInfo.ImportsName, new[] { "StartService" }))
                {
                    suspiciousData.Add("UseService");
                    score += 15;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "CopyFile" }) && ContainsSuspiciousApi(peInfo.ImportsName, new[] { "CreateDirectory" }) && ContainsSuspiciousApi(peInfo.ImportsName, new[] { "DeleteFile" }) && ContainsSuspiciousApi(peInfo.ImportsName, new[] { "GetFullPathName" }))
                {
                    score += 5;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "CreateObject" }))
                {
                    if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "Scriptlet.TypeLib", "Shell.Application", "Scripting.FileSystemObject" }))
                    {
                        score += 15;
                    }
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "GetDlgItemInt", "GetDlgItemText", "GetDlgItemTextA" }))
                {
                    score += 15;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "InternetReadFile", "FtpGetFile", "URLDownloadToFile" }))
                {
                    if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "WinExec" }) && ContainsSuspiciousApi(peInfo.ImportsName, new[] { "RegCreateKey" }))
                    {
                        score += 20;

                        if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "MoveFile", "CopyFile" }))
                        {
                            score += 10;
                        }
                    }
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "CallNextHookEx", "SetWindowsHook" }))
                {
                    suspiciousData.Add("AddHook");
                    score += 20;
                }
                else if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "Hook" }))
                {
                    suspiciousData.Add("LikeAddHook");
                    score += 15;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "WriteConsole" }))
                {
                    score += 5;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "GetModuleFileName", "GetModuleHandle" }))
                {
                    score += 20;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "WNetAddConnection" }))
                {
                    score += 15;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "CopyScreen" }))
                {
                    score += 15;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "ExitWindows" }))
                {
                    score += 5;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "URLDownloadToFile" }))
                {
                    score += 15;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "URLDownloadToCacheFile" }))
                {
                    score -= 15;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "mouse_event", "keydb_event" }))
                {
                    score += 15;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "SetPriorityClass" }))
                {
                    score += 15;
                }

                if (ContainsSuspiciousApi(peInfo.ImportsName, new[] { "EnumAudioEndpoints" }))
                {
                    suspiciousData.Add("LikeSandboxBypass");
                    score += 15;
                }
            }

            // 深度扫描
            if (deepScan)
            {
                if (ContainsSuspiciousContent(fileContent, new[] { ".sys" }))
                {
                    suspiciousData.Add("UseDriver");
                    score += 10;
                }

                if (ContainsSuspiciousContent(fileContent, new[] { "Virtual" }))
                {
                    score += 20;
                }

                if (ContainsSuspiciousContent(fileContent, new[] { "BlackMoon" }))
                {
                    suspiciousData.Add("BlackMoon");
                    score += 15;
                }

                if (ContainsSuspiciousContent(fileContent, new[] {
                    "wsctrlsvc", "ESET", "zhudongfangyu", "avp", "avconsol",
                    "ASWSCAN", "KWatch", "QQPCTray", "360tray", "360sd", "ccSvcHst",
                    "f-secure", "KvMonXP", "RavMonD", "Mcshield", "ekrn", "kxetray",
                    "avcenter", "avguard", "Sophos", "safedog"}))
                {
                    suspiciousData.Add("AVKiller");
                    score += 20;
                }

                if (ContainsSuspiciousContent(fileContent, new[] { "DelegateExecute", "fodhelper.exe" }))
                {
                    suspiciousData.Add("UACBypass");
                    score += 20;
                }

                if (ContainsSuspiciousContent(fileContent, new[] { "sandboxie", "vmware - tray", "Detonate", "Vmware", "VMWARE", "Sandbox", "SANDBOX" }))
                {
                    suspiciousData.Add("SandboxBypass");
                    score += 20;
                }
            }

            // 将附加数据拼接到extra变量
            extra = string.Join(" ", suspiciousData);

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

        public static bool IsFileDigitallySignedAndValid(string filePath)
        {
            try
            {
                X509Certificate2 cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));

                X509Chain chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(30);
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

                return chain.Build(cert);
            }
            catch
            {
                return false;
            }
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
            if (apis == null)
            {
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