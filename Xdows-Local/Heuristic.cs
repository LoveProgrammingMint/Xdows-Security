using PeNet;
using System.Buffers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static Xdows_Local.Core;

namespace Xdows_Local
{
    public static class Heuristic
    {
        private struct Rule(string[][] keywords, int score, string suspiciousData)
        {
            public string[][] Keywords = keywords;
            public int Score = score;
            public string SuspiciousData = suspiciousData;
        }
        private static readonly Rule[] Rules =
        [
            new Rule([["GetOpenFileName", "GetSaveFileName"]], -20, "FileDialog"),
            new Rule([["LoadLibrary"], ["GetProcAddress"]], 15, string.Empty),
            new Rule([["LoadLibrary"]], 10, string.Empty),
            new Rule([["SetFileAttributes"], ["FILE_ATTRIBUTE_HIDDEN"]], 20, string.Empty),
            new Rule([["SHFormatDrive"]], 20, string.Empty),
            new Rule([["RtlAdjustPrivilege"]], 20, string.Empty),
            new Rule([["HideCurrentProcess"]], 20, string.Empty),
            new Rule([["CreateService"], ["StartService"]], 15, "UseService"),
            new Rule([["CopyFile"], ["CreateDirectory"], ["DeleteFile"], ["GetFullPathName"]], 5, string.Empty),
            new Rule([["CreateObject"], ["Scriptlet.TypeLib", "Shell.Application", "Scripting.FileSystemObject"]], 15, string.Empty),
            new Rule([["GetDlgItemInt", "GetDlgItemText"]], 15, string.Empty),
            new Rule([["InternetReadFile", "FtpGetFile", "URLDownloadToFile"], ["WinExec"], ["RegCreateKey"]], 20, string.Empty),
            new Rule([["InternetReadFile", "FtpGetFile", "URLDownloadToFile"], ["MoveFile", "CopyFile"]], 5, string.Empty),
            new Rule([["CallNextHook", "SetWindowsHook"]], 15, "AddHook"),
            new Rule([["_"]], 5, string.Empty),
            new Rule([["GetLastError"]], 5, string.Empty),
            new Rule([["FlushInstruction"]], 5, string.Empty),
            new Rule([["WriteConsole"]], -5, string.Empty),
            new Rule([["VirtualAlloc", "VirtualFree", "VirtualProtect", "VirtualQuery"]], 15, "ModifyMemory"),
            new Rule([["GetModuleFileName", "GetModuleHandle"]], 20, string.Empty),
            new Rule([["WNetAddConnection"]], 15, string.Empty),
            new Rule([["CopyScreen"]], 15, string.Empty),
            new Rule([["ExitWindows"]], 5, string.Empty),
            new Rule([["URLDownloadToFile"]], 15, string.Empty),
            new Rule([["URLDownloadToCacheFile"]], -15, string.Empty),
            new Rule([["mouse_event ", "keybd_event "]], 15, "InputSimulate"),
            new Rule([["SetPriorityClass"]], 15, string.Empty),
            new Rule([["CryptGenRandom"]], 15, string.Empty),
            new Rule([["EnumAudioEndpoints"]], 15, "LikeSandboxBypass"),
            new Rule([["AdjustTokenPrivileges", "LookupPrivilegeValue", "OpenProcessToken"]], 10, string.Empty),
            new Rule([["CryptAcquireContext"]], 10, string.Empty),
            new Rule([["CreateRemoteThread"]], 10, string.Empty),
            new Rule([["InternetOpen", "InternetConnect", "HttpSendRequest"]], 5, string.Empty),
            new Rule([["RegCreateKey", "RegSetValue"]], 5, string.Empty),
            new Rule([["WriteProcessMemory "], ["CreateRemoteThread "]], 15, "ProcessInjection"),
            new Rule([["OpenProcess "]], 5, string.Empty),
            new Rule([["NtCreateThread", "ZwCreateThread"]], 15, "NativeThreadInject"),
            new Rule([["OpenProcessToken "], ["DuplicateToken"], ["ImpersonateLoggedOnUser"]], 20, "TokenTheft"),
            new Rule([["ZwUnmapViewOfSection ", "NtUnmapViewOfSection"], ["ZwMapViewOfSection", "NtMapViewOfSection"]], 25, "ProcessHollowing"),
            new Rule([["CreateProcess"], ["CREATE_SUSPENDED "], ["ResumeThread "]], 15, "SuspendedProcessInject"),
            new Rule([["QueueUserAPC", "NtQueueApcThread"]], 15, "APCInject"),
            new Rule([["SetThreadContext "], ["GetThreadContext "]], 15, "ThreadHijack"),
            new Rule([["GetAsyncKeyState "]], 10, "KeyloggerPolling"),
            new Rule([["ShellExecute"]], 5, string.Empty),
            new Rule([["GetProcessImageFileName"]], 5, string.Empty),
        ];
        public static (int score, string extra) Evaluate(string path, PeFile peFile, PEInfo peInfo, bool deepScan)
        {
            var extra = string.Empty;
            var score = 0;
            var suspiciousData = new List<string>();

            var fileExtension = GetExtStrings(path);

            var fileContent = peFile.RawFile.ToArray();
            if (fileExtension.Length > 0)
            {
                string[] docExts = [".doc", ".ppt", ".xls", ".csv"];
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
                        var attrs = File.GetAttributes(path);
                        if ((attrs & FileAttributes.Hidden) != 0)
                        {
                            score += 20;
                            suspiciousData.Add("StartupHidden");
                        }
                    }
                    catch { }
                }
            }

            if (peFile.IsExe || peFile.IsDll || peFile.IsDriver) // .NET文件无法分析
            {
                int code = FileDigitallySignedAndValid(path, peFile);
                if (code == 50)
                    return (0, string.Empty);
                score -= code;

                var resourceTask = CheckResourceSectionForPacking(peFile);
                var packingTask = CheckPackingSignatures(peFile);

                int tempScore = resourceTask;
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

                    var imports = peInfo.ImportsName;
                    bool Has(params string[] keys) => ContainsSuspiciousApi(imports, keys);

                    bool hookHandled = false;

                    foreach (var r in Rules)
                    {
                        bool matched = true;
                        foreach (var group in r.Keywords)
                        {
                            if (!group.Any(k => Has(k)))
                            {
                                matched = false;
                                break;
                            }
                        }

                        if (!matched) continue;
                        score += r.Score;
                        if (!string.IsNullOrEmpty(r.SuspiciousData)) suspiciousData.Add(r.SuspiciousData);
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
                bool t1Result = false, t2Result = false, t3Result = false, t4Result = false, t5Result = false, t6Result = false, t7Result = false;
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

                // 合并结果
                if (t1Result) { suspiciousData.Add("UseDriver"); score += 10; }
                if (t2Result) { score += 20; }
                if (t3Result) { suspiciousData.Add("BlackMoon"); score += 15; }
                if (t4Result) { suspiciousData.Add("AVKiller"); score += 20; }
                if (t5Result) { suspiciousData.Add("BugsExploit"); score += 30; }
                if (t6Result) { suspiciousData.Add("SandboxBypass"); score += 20; }
                if (t7Result) { suspiciousData.Add("LikeChangeMBR"); score += 20; }
            }

            // 将附加数据拼接到extra变量
            extra = string.Join(" ", suspiciousData);

            return (score, extra);
        }
        public static bool CheckPackingSignatures(PeFile pe)
        {
            var raw = pe.RawFile.ToArray();
            if (raw.Length > 0x40 &&
                raw[0x40] == 0x55 && raw[0x41] == 0x50 &&
                raw[0x42] == 0x58 && raw[0x43] == 0x30)
                return true;
            uint ep = pe.ImageNtHeaders?.OptionalHeader.AddressOfEntryPoint ?? 0;
            if (ep > raw.Length * 0.8)
                return true;

            return false;
        }
        public static int CheckResourceSectionForPacking(PeFile pe)
        {
            int score = 0;
            var resRva = pe.ImageNtHeaders?.OptionalHeader.DataDirectory[2].VirtualAddress ?? 0;
            if (resRva == 0) score += 10;
            else if (resRva < 4096) score += 5;
            var rsrc = pe.ImageSectionHeaders?
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
        private static string[] GetExtStrings(string path)
        {
            if (string.IsNullOrEmpty(path)) return new string[0];

            List<string> extensions = [];
            int lastSlashIndex = path.LastIndexOfAny(new char[] { '\\', '/' });
            int extStartIndex = path.LastIndexOf('.');

            if (extStartIndex > lastSlashIndex)
            {
                string extension = path[(extStartIndex + 1)..].ToLowerInvariant();
                extensions.Add(extension);
            }

            return [.. extensions];
        }



        private static readonly HashSet<string> _trustedThumbprints = new(StringComparer.OrdinalIgnoreCase)
           {
               "3B77DB29AC72AA6B5880ECB2ED5EC1EC6601D847",
               "FACDE3D80E99AFCC15E08AC5A69BD22785287F79",
               "AEB9B61E47D91C42FFF213992B7810A3D562FB12",
               "F6EECCC7FF116889C2D5466AE7243D7AA7698689",
               "3C9202BAFACBF9B5E3F1F1AC732C6BF4F98B4F27",
               "81915C173D7FFCBF49EAA8CF7594696B29A035E1",
               "B2732A60F9D0E554F756D87E7446A20F216B4F73",
               "72A2EC23DA8479E173F0130F1304ED9555DFADDA",
               "48B2486F389C9927957299BDFD24C2ABEF9D15DB",
               "07A5509B253A840EB98F221B72B732C9482342C8",
               "6ACE61BAE3F09F4DD2697806D73E022CBFE70EB4",
               "D30F05F637E605239C0070D1EA9860D434AC2A94",
               "3B1EFD3A66EA28B16697394703A72CA340A05BD5",
               "71F53A26BB1625E466727183409A30D03D7923DF",
               "580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D",
               "D8FB0CC66A08061B42D46D03546F0D42CBC49B7C",
               "5A858500A0262E237FBA6BFEF80FA39C59ECEE76",
               "F252E794FE438E35ACE6E53762C0A234A2C52135",
               "8F43288AD272F3103B6FB1428485EA3014C0BCFE",
               "AD2F5CD0B177DB47919DD362BD7A8A1C054D9A7A",
               "F6B86C0B3C495D7DE692FFCDBD702813605CFF56",
               "34C7F85D476F6AAA50F9A10F82EEE35147297586",
               "587116075365AA15BCD8E4FA9CB31BE372B5DE51",
               "F7FB87F1830A5A3A22C40D076E68DF1E1B7B2BFC",
               "A32F56A57D828436FAD2AD4EC1FADB66340C8D5A",
               "AFE5D244A8D1194230FF479FE2F897BBCD7A8CB4",
               "8F985BE8FD256085C90A95D3C74580511A1DB975",
               "1226440E939A24EB202C2A517CE13F8326EFDE60",
               "245D262748012A4FE6CE8BA6C951A4C4AFBC3E5D",
               "F48E0797B27895D9C4D6B2FA4D462B9CBB2E9AA7",
               "8BFE3107712B3C886B1C96AAEC89984914DC9B6B",
               "35356734934600CD9FAB91E0FDB98B175517149E",
               "D7E69D8FF7E41041D146BED34ED5919F42608525",
               "1F36D9C751BC62BA33171D973937D3A65CE5A0D6",
               "94C95DA1E850BD85209A4A2AF3E1FB1604F9BB66",
               "2B8F1B57330DBBA2D07A6C51F70EE90DDAB9AD8E",
               "734B95B353850AA4742674CBA48A2EF7451F6B62",
               "EC5F0D7EE2327688384B4FDF5D7633553A0D055F",
               "2F5540201B5799E6A3E2131C3D05753D23879FE0",
               "A6EEC189212E4C3F109EFBBBA756A0C2360E7D01",
               "C580C0EDFF9E96214ABCBF105E961CC3846AB1E1",
               "ABDCA79AF9DD48A0EA702AD45260B3C03093FB4B",
               "93859EBF98AFDEB488CCFA263899640E81BC49F1",
               "3036E3B25B88A55B86FC90E6E9EAAD5081445166",
               "A43489159A520F0D93D032CCAF37E7FE20A8B419",
               "F55115D2439CE0A7529FFAAEA654BE2C71DCE955",
               "98ED99A67886D020C564923B7DF25E9AC019DF26",
               "3CAF9BA2DB5570CAF76942FF99101B993888E257",
               "CDD4EEAE6000AC7F40C3802C171E30148030C072",
               "8740DF4ACB749640AD318E4BE842F72EC651AD80",
               "772B07B19C91CBF81994E4FCF0A664ECCA65F36E",
               "BB7908CB899DEE33CFDEF11A28C36BB6389A97B8",
               "0185FF9961FF0AA2E431817948C28E83D3F3EC70",
               "CCBBF9E1485AF63CE47ABF8E9E648C2504FC319D",
               "09A1AA05288E952C901821DEAECE78D148D2E4D2",
               "066AC370EDEBCD12DAC192F3B170FC6DECF2D0D4",
               "E942D27A35DCBBE072872AD9E9E0AC4C948A7864",
               "4BAEA1454B8D5DC845BDE7A2D9754FABC221267C",
               "C2048FB509F1C37A8C3E9EC6648118458AA01780",
               "5A35DBEBADCB43E9C20E4F9706CCBDD0015E9740",
               "72105B6D5F370B62FD5C82F1512F7AD7DEE5F2C0",
               "F9A7CF9FBE13BAC767F4781061332DA6E8B4E0EE",
               "B5993E35886D972F357CC0B7FB87EC5B470EE298",
               "B11749523FFBE04C25D85464D245FCFB52DD318D",
               "197B6F30B724C79A739DBBE52227F6181BEAB688",
               "77A10EBF07542725218CD83A01B521C57BC67F73",
               "190326D56FDAABBCDA573244CDB845CE2BE0C8BF",
               "8930E09944CDB3BB1ACBFE90606C62627E2BD9A7",
               "2485A7AFA98E178CB8F30C9838346B514AEA4769",
               "A5BCE29A2944105E0E25B626120264BB03499052",
               "58DA14F4C5941747B995956FDC89B4E3AAE47B8F",
               "63D724AEA7B5DE31A77BEF57B1314F20804844F4",
               "4766643B74115F54199758FE2CA65F7C546D9071",
               "805F96DBE404CD7C583F996836267255B467B9E3",
               "FAFB6925EBA28DCDCE5440F3C2B79616F7B597E8",
               "491F8966B4C63946277E87BFAD23040E0A3E796F",
               "33683BF769C7F15DACB73CBAE104896C54EB5762",
               "D1BD4C68D18A169DE843512EA6AADCAE10DC6A9D",
               "33683BF769C7F15DACB73CBAE104896C54EB5762",
               "5557E07D9DB356586113151D07407C8AF8607FAD",
               "2C50C512FF08ABBFFA158D325212F714ACA0E6CB",
               "9EF6B7D15459D05DCB15B5758A0F93FF30026A26",
               "5E265E9F104C5EF8A45E8E00E1ECA37E0581946A",
               "864BED1A9B0E5CFB6759BD14C6075838E6B3CFD4",
               "1406D59C034E6827C041048E522D08620C62214E",
               "7913DE9D7ED4EEEE790FF0680A4C802C1BC832AB",
               "4AC2A265A90105986DCB9EC573B6465F888B391B",
               "617C4EDB4F205FCA0E5C07B9C52AA8D695FD122C",
               "0A518324A48A250A4579DC9E96539CB44725B38C",
               "CCF766B7047842C79942F2C2DA0B4876E5DB3F37",
               "3723D4D6F69F5999BC6216222A69886352EDBF75",
               "3AD862FD74E4293CF4691B615D3EE3B6C8696569",
               "D21CB8B4958C36958AC6717D74DBCD585DD36D1B",
               "1D99AB7BD8636E6BF29AC4889878F4A0C339D020",
               "C464F76F379BC638ACFE143079D6AAD75D74AF5B",
               "D05994A6CB7A51F5EADB48783F5610822DF98294",
               "617C4EDB4F205FCA0E5C07B9C52AA8D695FD122C",
               "9E591EAA53E5BBAC32DCFE3915B2B9FA2406B112",
               "EA2F8CBC69A1A01142A1EDD8B1256FECBC1D9F2D",
               "607A3EDAA64933E94422FC8F0C80388E0590986C",
               "D05994A6CB7A51F5EADB48783F5610822DF98294",
               "AF1D4B6430343A151B41572E158103A029972DF9",
               "DA53BFC80A424095652053F05886C18348B79906",
               "CB07B24591B6AA1B5D98D129D9BD62DB272E1F89",
               "6663D5C4FDAF9EFD5F823A26C9C410DC9928C44A",
               "5F9970D4CE262509EF94FB6215B61AAB5B6D9649",
               "4F05C0A4989C035908E281D6F64FB24EA81AB6AF",
               "858BE53EE180746E5ED1B18FFB8186B8676E312A",
               "9B587CF3A14FEE535ECBF893A16AED5E4539612A",
               "CF9252B27108BC3CD10B568EF056BBC647FEE80C",
               "F8493437F6153F7286AC844316E5A83859A2633F",
               "4AC2A265A90105986DCB9EC573B6465F888B391B",
               "400E0E8B63B730243F8AB360F5565C5501BDDF7C",
               "BED5AC819A7E3C26B9214287C9F0E2AD9EBC3822",
               "14D58A0DEBCD00348B62ED97DFB171C9CAEE281F",
               "8D32122C4A3F3F8F4AF472BE21E45F50A406487E",
               "0CCD90546AC8069C4FCF28808779198D52BDFC3D",
               "7943A31F99601A930BD88AE53BE745BB6B579EDE",
               "C2DED3FF5C28973EBD4773E6CF15BF933B707CE0",
               "B9F05062ED02D4C3B1DB7DB679B963CF5E9BC126",
               "A13A400ED544756DC33852858E45E092F59F9F59",
               "C76E45454AB62D7457212755503FD306B652BBF5",
               "5C3523B19C304DE2A320E19FD757B3957D69BDD4",
               "CD22D7228E666132008B90BB8D2D143BFD36D4EF",
               "2C84136BC977C46EC8144CDD45A56FBBFAA86E95",
               "ACAED4BE8C729A6AE5F4F82F5F183A9C4EBE7AE3",
               "5D37C15025DAF2656F152207714B7FA36753540A",
               "3386115908DC1CA02B7A0EC8CBAFC468FB37362F",
               "A404AAA6172FBDA598BA772FDEFACFBE0B19BD00",
               "D2CE36DA67676E4369780EAFA16CAEA4BB088951",
               "DAEAE9A4AB202094DE9DB749A928AE674EC8D040",
               "7CE867B4E3F3F5CCBD7DCF8BFA3187D762F9EF00",
               "F49CC5386EC3F9A5BE4E8611C170954422CFC1DB",
               "AD2801EFB6FD0006B0985EBE79011B5855E1A6F8",
               "E1B5824EE85186B91E65DB3E75867F59E35CF4AB",
               "5E32D2C14376A70EFBD34728ED4A8ACEBEFE3592",
               "54CB0488F03C61AFAA04C155B457FE283E6EA02E",
               "0F55B47074C6B8D76B79ECF07EA9FC92BDA8B87D",
           };
        public static int FileDigitallySignedAndValid(string filePath, PeFile pe)
        {
            try
            {
                if (filePath.Contains(@":\Windows", StringComparison.OrdinalIgnoreCase))
                    return 50;
                var auth = pe.SigningAuthenticodeCertificate;
                if (auth == null) return 0;

                var chain = new X509Chain
                {
                    ChainPolicy = {
                        RevocationMode = X509RevocationMode.Offline,
                        RevocationFlag = X509RevocationFlag.ExcludeRoot,
                        UrlRetrievalTimeout = TimeSpan.FromSeconds(30),
                        VerificationFlags = X509VerificationFlags.NoFlag
                    }
                };

                bool chainOk = chain.Build(auth);
                bool isTrusted = chain.ChainElements
                                      .Any(el => _trustedThumbprints.Contains(el.Certificate.Thumbprint));
                if (isTrusted) return 60;

                if (auth.NotAfter <= DateTime.Now) return -10;

                bool revoked = chain.ChainElements
                                    .Any(el => el.ChainElementStatus.Any(s => s.Status == X509ChainStatusFlags.Revoked));
                if (revoked) return -5;

                return chainOk ? 5 : 0;
            }
            catch { return 0; }
        }

        private static bool IsSuspiciousDoc(byte[] fileContent)
        {
            if (fileContent.Length == 0) return false;
            var data = fileContent.AsSpan();
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
        private static bool ContainsSuspiciousApi(string[] apis, string[] keywords)
        {
            if (apis == null)
            {
                return false;
            }
            return keywords.Any(keyword => apis.Any(api => api.Contains(keyword)));
        }
        private static int CountSuspiciousApiOccurrences(string[] apis, string[] keywords)
        {
            if (apis == null || keywords == null || keywords.Length == 0)
                return 0;

            return apis.Count(api =>
                api != null && keywords.Any(keyword =>
                    keyword != null && api.Contains(keyword)));
        }
        private static bool ContainsSuspiciousContent(byte[] fileContent, string[] keywords)
        {
            if (fileContent.Length == 0) return false;
            ReadOnlySpan<byte> data = fileContent;

            Span<byte> buffer = stackalloc byte[1024];

            byte[]? oversizedBuffer = null;
            try
            {
                foreach (var keyword in keywords)
                {
                    int maxBytes = Encoding.UTF8.GetMaxByteCount(keyword.Length);

                    Span<byte> tempBuf = maxBytes <= buffer.Length
                        ? buffer
                        : (oversizedBuffer ??= ArrayPool<byte>.Shared.Rent(maxBytes));

                    int written = Encoding.UTF8.GetBytes(keyword, tempBuf);
                    if (data.IndexOf(tempBuf[..written]) >= 0)
                        return true;
                }
            }
            finally
            {
                if (oversizedBuffer != null) ArrayPool<byte>.Shared.Return(oversizedBuffer);
            }

            return false;
        }
    }
}