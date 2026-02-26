using PeNet;
using System.Buffers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static Xdows_Local.Core;

namespace Xdows_Local
{
    public static class Heuristic
    {
        private struct Rule(String[][] keywords, Int32 score, String suspiciousData)
        {
            public String[][] Keywords = keywords;
            public Int32 Score = score;
            public String SuspiciousData = suspiciousData;
        }

        private static readonly Rule[] Rules =
        [
            new Rule([["GetOpenFileName", "GetSaveFileName"]], -20, "FileDialog"),
            new Rule([["LoadLibrary"], ["GetProcAddress"]], 15, String.Empty),
            new Rule([["LoadLibrary"]], 10, String.Empty),
            new Rule([["SetFileAttributes"], ["FILE_ATTRIBUTE_HIDDEN"]], 20, String.Empty),
            new Rule([["SHFormatDrive"]], 20, String.Empty),
            new Rule([["RtlAdjustPrivilege"]], 20, String.Empty),
            new Rule([["HideCurrentProcess"]], 20, String.Empty),
            new Rule([["CreateService"], ["StartService"]], 15, "UseService"),
            new Rule([["CopyFile"], ["CreateDirectory"], ["DeleteFile"], ["GetFullPathName"]], 5, String.Empty),
            new Rule([["CreateObject"], ["Scriptlet.TypeLib", "Shell.Application", "Scripting.FileSystemObject"]], 15, String.Empty),
            new Rule([["GetDlgItemInt", "GetDlgItemText"]], 15, String.Empty),
            new Rule([["InternetReadFile", "FtpGetFile", "URLDownloadToFile"], ["WinExec"], ["RegCreateKey"]], 20, String.Empty),
            new Rule([["InternetReadFile", "FtpGetFile", "URLDownloadToFile"], ["MoveFile", "CopyFile"]], 5, String.Empty),
            new Rule([["CallNextHook", "SetWindowsHook"]], 15, "AddHook"),
            new Rule([["_"]], 5, String.Empty),
            new Rule([["free"]], 5, String.Empty),
            new Rule([["GetLastError"]], 5, String.Empty),
            new Rule([["FlushInstruction"]], 5, String.Empty),
            new Rule([["WriteConsole"]], -5, String.Empty),
            new Rule([["VirtualAlloc", "VirtualFree", "VirtualProtect", "VirtualQuery"]], 15, "ModifyMemory"),
            new Rule([["GetModuleFileName", "GetModuleHandle"]], 20, String.Empty),
            new Rule([["WNetAddConnection"]], 15, String.Empty),
            new Rule([["CopyScreen"]], 15, String.Empty),
            new Rule([["ExitWindows"]], 5, String.Empty),
            new Rule([["URLDownloadToFile"]], 15, String.Empty),
            new Rule([["URLDownloadToCacheFile"]], -15, String.Empty),
            new Rule([["mouse_event ", "keybd_event "]], 15, "InputSimulate"),
            new Rule([["SetPriorityClass"]], 15, String.Empty),
            new Rule([["CryptGenRandom"]], 15, String.Empty),
            new Rule([["EnumAudioEndpoints"]], 15, "LikeSandboxBypass"),
            new Rule([["AdjustTokenPrivileges", "LookupPrivilegeValue", "OpenProcessToken"]], 10, String.Empty),
            new Rule([["CryptAcquireContext"]], 10, String.Empty),
            new Rule([["CreateRemoteThread"]], 10, String.Empty),
            new Rule([["InternetOpen", "InternetConnect", "HttpSendRequest"]], 5, String.Empty),
            new Rule([["RegCreateKey", "RegSetValue"]], 5, String.Empty),
            new Rule([["WriteProcessMemory "], ["CreateRemoteThread "]], 15, "ProcessInjection"),
            new Rule([["OpenProcess "]], 5, String.Empty),
            new Rule([["NtCreateThread", "ZwCreateThread"]], 15, "NativeThreadInject"),
            new Rule([["OpenProcessToken "], ["DuplicateToken"], ["ImpersonateLoggedOnUser"]], 20, "TokenTheft"),
            new Rule([["ZwUnmapViewOfSection ", "NtUnmapViewOfSection"], ["ZwMapViewOfSection", "NtMapViewOfSection"]], 25, "ProcessHollowing"),
            new Rule([["CreateProcess"], ["CREATE_SUSPENDED "], ["ResumeThread "]], 15, "SuspendedProcessInject"),
            new Rule([["QueueUserAPC", "NtQueueApcThread"]], 15, "APCInject"),
            new Rule([["SetThreadContext "], ["GetThreadContext "]], 15, "ThreadHijack"),
            new Rule([["GetAsyncKeyState "]], 10, "KeyloggerPolling"),
            new Rule([["ShellExecute"]], 5, String.Empty),
            new Rule([["GetProcessImageFileName"]], 5, String.Empty),
        ];

        public static (Int32 score, String extra) Evaluate(String path, PeFile peFile, PEInfo peInfo, Boolean deepScan)
        {
            String extra = String.Empty;
            Int32 score = 0;
            List<String> suspiciousData = [];

            String[] fileExtension = GetExtStrings(path);

            Byte[] fileContent = peFile.RawFile.ToArray();
            if (fileExtension.Length > 0)
            {
                String[] docExts = [".doc", ".ppt", ".xls", ".csv"];
                if (docExts.Any(docExt => path.Contains(docExt)))
                {
                    if (IsSuspiciousDoc(fileContent))
                    {
                        score += 10;
                        suspiciousData.Add("DocVirus");
                    }
                }
                else if (fileExtension[^1] == "fne")
                {
                    score += 20;
                    suspiciousData.Add("EComponent");
                }

                if (fileExtension.Length > 1 && fileExtension[^1] != "bak")
                {
                    score += 20;
                }

                if (fileExtension[^1] == "exe" &&
                    (path.Contains(@"\Start Menu\Programs\Startup\", StringComparison.OrdinalIgnoreCase) ||
                     path.Contains(@"\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\", StringComparison.OrdinalIgnoreCase)))
                {
                    try
                    {
                        FileAttributes attrs = File.GetAttributes(path);
                        if ((attrs & FileAttributes.Hidden) != 0)
                        {
                            score += 20;
                            suspiciousData.Add("StartupHidden");
                        }
                    }
                    catch { }
                }
            }

            if (peFile.IsExe || peFile.IsDll || peFile.IsDriver)
            {
                Int32 code = FileDigitallySignedAndValid(path, peFile);
                if (code == 50)
                    return (0, String.Empty);
                score -= code;

                Int32 resourceTask = CheckResourceSectionForPacking(peFile);
                Boolean packingTask = CheckPackingSignatures(peFile);

                Int32 tempScore = resourceTask;
                if (tempScore > 0)
                {
                    score += tempScore;
                    suspiciousData.Add("AbnormalResources");
                }

                if (packingTask)
                {
                    score += 10;
                    suspiciousData.Add("PackingSignatures");
                }

                if (peFile.IsDotNet || peFile.IsDriver)
                {
                    score += 5;
                }

                if (peInfo.ImportsDll != null)
                {
                    if (ContainsSuspiciousApi(peInfo.ImportsDll, ["KERNEL32.dll"]))
                    {
                        score += 5;
                    }
                }

                if (peInfo.ImportsName != null)
                {
                    score += peInfo.ImportsName.Length <= 50 ? 5 : -5;

                    String[] imports = peInfo.ImportsName;
                    Boolean Has(params String[] keys) => ContainsSuspiciousApi(imports, keys);

                    Boolean hookHandled = false;

                    foreach (Rule r in Rules)
                    {
                        Boolean matched = true;
                        foreach (String[] group in r.Keywords)
                        {
                            if (!group.Any(k => Has(k)))
                            {
                                matched = false;
                                break;
                            }
                        }

                        if (!matched) continue;
                        score += r.Score;
                        if (!String.IsNullOrEmpty(r.SuspiciousData)) suspiciousData.Add(r.SuspiciousData);
                        if (r.SuspiciousData == "AddHook") hookHandled = true;
                    }

                    if (!hookHandled)
                    {
                        tempScore = CountSuspiciousApiOccurrences(imports, ["Hook"]);
                        if (tempScore > 0)
                        {
                            suspiciousData.Add("LikeAddHook");
                            score += tempScore * 2;
                        }
                    }

                    if (Has("SetFilePointer"))
                    {
                        score += 15;
                        if (deepScan && Has("WriteFile") && ContainsSuspiciousContent(fileContent, ["physicaldrive0"]))
                        {
                            score += 5;
                            suspiciousData.Add("ModifyMBR");
                        }
                    }

                    if (Has("VirtualAlloc", "VirtualFree", "VirtualProtect", "VirtualQuery"))
                    {
                        score += imports.Length <= 50 ? 15 : -10;
                    }
                }
            }

            if (deepScan)
            {
                Boolean t1Result = false, t2Result = false, t3Result = false, t4Result = false, t5Result = false, t6Result = false, t7Result = false;
                Parallel.Invoke(
                    () => t1Result = ContainsSuspiciousContent(fileContent, [".sys"]),
                    () => t2Result = ContainsSuspiciousContent(fileContent, ["Virtual"]),
                    () => t3Result = ContainsSuspiciousContent(fileContent, ["BlackMoon"]),
                    () => t4Result = ContainsSuspiciousContent(fileContent, [
                        "wsctrlsvc", "ESET", "zhudongfangyu", "avp", "avconsol",
                        "ASWSCAN", "KWatch", "QQPCTray", "360tray", "360sd", "ccSvcHst",
                        "f-secure", "KvMonXP", "RavMonD", "Mcshield", "ekrn", "kxetray",
                        "avcenter", "avguard", "Sophos", "safedog"
                    ]),
                    () => t5Result = ContainsSuspiciousContent(fileContent, ["DelegateExecute", "fodhelper.exe", "OSDATA", "wow64log.dll"]),
                    () => t6Result = ContainsSuspiciousContent(fileContent, ["sandboxie", "vmware - tray", "Detonate", "Vmware", "VMWARE", "Sandbox", "SANDBOX"]),
                    () => t7Result = ContainsSuspiciousContent(fileContent, ["PhysicalDrive0"])
                );

                if (t1Result) { suspiciousData.Add("UseDriver"); score += 10; }
                if (t2Result) { score += 20; }
                if (t3Result) { suspiciousData.Add("BlackMoon"); score += 15; }
                if (t4Result) { suspiciousData.Add("AVKiller"); score += 20; }
                if (t5Result) { suspiciousData.Add("BugsExploit"); score += 30; }
                if (t6Result) { suspiciousData.Add("SandboxBypass"); score += 20; }
                if (t7Result) { suspiciousData.Add("LikeChangeMBR"); score += 20; }
            }

            extra = String.Join(" ", suspiciousData);

            return (score, extra);
        }

        public static Boolean CheckPackingSignatures(PeFile pe)
        {
            Byte[] raw = pe.RawFile.ToArray();
            if (raw.Length > 0x40 &&
                raw[0x40] == 0x55 && raw[0x41] == 0x50 &&
                raw[0x42] == 0x58 && raw[0x43] == 0x30)
                return true;

            UInt32 ep = pe.ImageNtHeaders?.OptionalHeader.AddressOfEntryPoint ?? 0;
            if (ep > raw.Length * 0.8)
                return true;

            return false;
        }

        public static Int32 CheckResourceSectionForPacking(PeFile pe)
        {
            Int32 score = 0;
            UInt32 resRva = pe.ImageNtHeaders?.OptionalHeader.DataDirectory[2].VirtualAddress ?? 0;
            if (resRva == 0) score += 10;
            else if (resRva < 4096) score += 5;

            PeNet.Header.Pe.ImageSectionHeader? rsrc = pe.ImageSectionHeaders?
                .FirstOrDefault(s => s.Name
                    .TrimEnd('\0')
                    .Equals(".rsrc", StringComparison.OrdinalIgnoreCase));

            if (rsrc != null)
            {
                if (rsrc.VirtualSize == 0 || rsrc.SizeOfRawData == 0)
                    score += 10;
                else if (rsrc.VirtualSize > 1024 * 1024)
                    score += 5;
                else if (rsrc.SizeOfRawData < 1024 && rsrc.VirtualSize > 1024)
                    score += 15;
            }

            return score;
        }

        private static String[] GetExtStrings(String path)
        {
            if (String.IsNullOrEmpty(path)) return [];

            List<String> extensions = [];
            Int32 lastSlashIndex = path.LastIndexOfAny(['\\', '/']);
            Int32 extStartIndex = path.LastIndexOf('.');

            if (extStartIndex > lastSlashIndex)
            {
                String extension = path[(extStartIndex + 1)..].ToLowerInvariant();
                extensions.Add(extension);
            }

            return [.. extensions];
        }

        private static readonly Lazy<HashSet<String>> _trustedThumbprintsLazy = new(() =>
        {
            var set = new HashSet<String>(StringComparer.OrdinalIgnoreCase);
            var path = Path.Combine(AppContext.BaseDirectory, "trusted-thumbprints.txt");
            if (File.Exists(path))
            {
                foreach (var line in File.ReadAllLines(path))
                {
                    var trimmed = line.Trim();
                    if (trimmed.Length == 40 && trimmed.All(c => "0123456789ABCDEFabcdef".Contains(c)))
                        set.Add(trimmed);
                }
            }
            return set;
        });
        private static HashSet<String> _trustedThumbprints => _trustedThumbprintsLazy.Value;

        public static Int32 FileDigitallySignedAndValid(String filePath, PeFile pe)
        {
            try
            {
                if (filePath.Contains(@":\Windows", StringComparison.OrdinalIgnoreCase))
                    return 50;

                X509Certificate2? auth = pe.SigningAuthenticodeCertificate;
                if (auth == null) return 0;

                X509Chain chain = new()
                {
                    ChainPolicy = {
                        RevocationMode = X509RevocationMode.Offline,
                        RevocationFlag = X509RevocationFlag.ExcludeRoot,
                        UrlRetrievalTimeout = TimeSpan.FromSeconds(30),
                        VerificationFlags = X509VerificationFlags.NoFlag
                    }
                };

                Boolean chainOk = chain.Build(auth);
                Boolean isTrusted = chain.ChainElements
                    .Any(el => _trustedThumbprints.Contains(el.Certificate.Thumbprint));

                if (isTrusted) return 60;

                if (auth.NotAfter <= DateTime.Now) return -10;

                Boolean revoked = chain.ChainElements
                    .Any(el => el.ChainElementStatus.Any(s => s.Status == X509ChainStatusFlags.Revoked));

                if (revoked) return -5;

                return chainOk ? 5 : 0;
            }
            catch { return 0; }
        }

        private static Boolean IsSuspiciousDoc(Byte[] fileContent)
        {
            if (fileContent.Length == 0) return false;
            ReadOnlySpan<Byte> data = fileContent.AsSpan();

            if (data.IndexOf("This program cannot be run"u8) >= 0) return true;
            if (data.IndexOf("LoadLibraryA"u8) >= 0) return true;
            if (data.IndexOf("RichN"u8) >= 0) return true;
            if (data.IndexOf("kernel32.dll"u8) >= 0) return true;
            if (data.IndexOf("Win32"u8) >= 0) return true;
            if (data.IndexOf("GetProcAddress"u8) >= 0) return true;
            if (data.IndexOf("邢"u8) >= 0 && data.IndexOf("唷"u8) >= 0)
            {
                if (data.IndexOf("Microsoft Office Word"u8) >= 0 ||
                    data.IndexOf("Microsoft Word"u8) >= 0) return false;
                return true;
            }

            return false;
        }

        private static Boolean ContainsSuspiciousApi(String[] apis, String[] keywords)
        {
            if (apis == null)
            {
                return false;
            }
            return keywords.Any(keyword => apis.Any(api => api.Contains(keyword)));
        }

        private static Int32 CountSuspiciousApiOccurrences(String[] apis, String[] keywords)
        {
            if (apis == null || keywords == null || keywords.Length == 0)
                return 0;

            return apis.Count(api =>
                api != null && keywords.Any(keyword =>
                    keyword != null && api.Contains(keyword)));
        }

        private static Boolean ContainsSuspiciousContent(Byte[] fileContent, String[] keywords)
        {
            if (fileContent.Length == 0) return false;
            ReadOnlySpan<Byte> data = fileContent;

            Span<Byte> buffer = stackalloc Byte[1024];
            Byte[]? oversizedBuffer = null;

            try
            {
                foreach (String keyword in keywords)
                {
                    Int32 maxBytes = Encoding.UTF8.GetMaxByteCount(keyword.Length);

                    Span<Byte> tempBuf = maxBytes <= buffer.Length
                        ? buffer
                        : (oversizedBuffer ??= ArrayPool<Byte>.Shared.Rent(maxBytes));

                    Int32 written = Encoding.UTF8.GetBytes(keyword, tempBuf);
                    if (data.IndexOf(tempBuf[..written]) >= 0)
                        return true;
                }
            }
            finally
            {
                if (oversizedBuffer != null) ArrayPool<Byte>.Shared.Return(oversizedBuffer);
            }

            return false;
        }
    }
}
