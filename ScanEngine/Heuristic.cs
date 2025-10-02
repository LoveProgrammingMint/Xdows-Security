using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
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
                int code = FileDigitallySignedAndValid(path,deepScan);
                if (code == 50)
                    return 0;
                score -= code;
                if (peInfo.ExportsName != null)
                {
                    if (DllScan.Scan(path, peInfo))
                        suspiciousData.Add("DllVirus");
                        score += 20;
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
        private static readonly HashSet<string> _trustedThumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
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
           };
        public static int FileDigitallySignedAndValid(string filePath,bool isDeepScan)
        {
            X509Certificate2? cert = null;
            try
            {
                cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));

                X509Chain chain = new X509Chain
                {
                    ChainPolicy =
                    {
                       RevocationMode = X509RevocationMode.Online,
                       RevocationFlag = X509RevocationFlag.ExcludeRoot,
                       UrlRetrievalTimeout = TimeSpan.FromSeconds(30),
                       VerificationFlags = X509VerificationFlags.NoFlag
                    }
                };

                bool chainOk = chain.Build(cert);
                if (isDeepScan && !AuthenticodeHashMatch(filePath)) return -10;
                bool isTrustedCertificate = chain.ChainElements
                                            .Any(el => _trustedThumbprints.Contains(el.Certificate.Thumbprint));
                if (isTrustedCertificate)
                    return 50;

                //SignedAndValid += string.Concat(
                //    chain.ChainElements
                //         .Select(el => el.Certificate.Thumbprint)
                //         .Where(t => !SignedAndValid.Contains($"\n{t},"))
                //         .Select(t => $"\n{t},"));
                if (cert.NotAfter <= DateTime.Now)
                    return -10;

                foreach (X509ChainElement el in chain.ChainElements)
                {
                    if (el.ChainElementStatus.Any(s =>
                            s.Status == X509ChainStatusFlags.Revoked))
                        return -10;
                }
                return chainOk ? 5 : 0;
            }
            catch
            {
                string? fp = GetCatalogCertSha256(filePath);

                //if (!string.IsNullOrEmpty(fp) && (!_trustedThumbprints.Contains(fp) && !SignedAndValid.Contains(fp)))
                //{
                //    SignedAndValid += "\n{fp},";
                //}
                return string.IsNullOrEmpty(fp) ? 0
                     : _trustedThumbprints.Contains(fp) ? 50
                     : 5;
            }
            finally
            {
                cert?.Dispose();
            }
        }
        private static bool AuthenticodeHashMatch(string filePath)
        {
            var fi = new Native.WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(Native.WINTRUST_FILE_INFO)),
                pcwszFilePath = filePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            var wd = new Native.WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(Native.WINTRUST_DATA)),
                dwUIChoice = 2,
                fdwRevocationChecks = Native.WTD_REVOKE_NONE,
                dwUnionChoice = Native.WTD_CHOICE_FILE,
                pFile = Marshal.AllocHGlobal(Marshal.SizeOf(fi)),
                dwProvFlags = Native.WTD_VERIFY_FILE_HASH_ONLY,
                dwStateAction = 1
            };
            Marshal.StructureToPtr(fi, wd.pFile, false);

            int hr = Native.WinVerifyTrust(IntPtr.Zero, Native.WINTRUST_ACTION_GENERIC_VERIFY_V2, ref wd);

            wd.dwStateAction = 2;
            Native.WinVerifyTrust(IntPtr.Zero, Native.WINTRUST_ACTION_GENERIC_VERIFY_V2, ref wd);
            Marshal.FreeHGlobal(wd.pFile);

            return hr == 0; // 0 = 哈希正确
        }
        private static class Native
        {
            public const uint WTD_VERIFY_FILE_HASH_ONLY = 0x0200;
            public const uint WTD_REVOKE_NONE = 0x0000;
            public const uint WTD_CHOICE_FILE = 1;

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct WINTRUST_DATA
            {
                public uint cbStruct;
                public IntPtr pPolicyCallbackData;
                public IntPtr pSIPClientData;
                public uint dwUIChoice;
                public uint fdwRevocationChecks;
                public uint dwUnionChoice;
                public IntPtr pFile;
                public uint dwStateAction;
                public IntPtr hWVTStateData;
                public IntPtr pwszURLReference;
                public uint dwProvFlags;
                public uint dwUIContext;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct WINTRUST_FILE_INFO
            {
                public uint cbStruct;
                public string pcwszFilePath;
                public IntPtr hFile;
                public IntPtr pgKnownSubject;
            }

            [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
            public static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
                                                    ref WINTRUST_DATA pWVTData);

            public static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        }
        public static string? GetCatalogCertSha256(string filePath)
        {
            IntPtr hFile = NativeMethods.CreateFile(filePath, NativeMethods.GENERIC_READ, NativeMethods.FILE_SHARE_READ, IntPtr.Zero, NativeMethods.OPEN_EXISTING, 0, IntPtr.Zero);
            if (hFile == NativeMethods.INVALID_HANDLE_VALUE) return null;

            int hashSize = 0;
            NativeMethods.CryptCATAdminCalcHashFromFileHandle(hFile, ref hashSize, null, 0);
            byte[] hash = new byte[hashSize];
            if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle(hFile, ref hashSize, hash, 0))
            {
                NativeMethods.CloseHandle(hFile);
                return null;
            }
            NativeMethods.CloseHandle(hFile);

            IntPtr hCatAdmin = IntPtr.Zero;
            if (!NativeMethods.CryptCATAdminAcquireContext(out hCatAdmin, IntPtr.Zero, 0)) return null;

            IntPtr hCatInfo = NativeMethods.CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, IntPtr.Zero);
            if (hCatInfo == IntPtr.Zero)
            {
                NativeMethods.CryptCATAdminReleaseContext(hCatAdmin, 0);
                return null;
            }

            var info = new NativeMethods.CATALOG_INFO { cbStruct = Marshal.SizeOf(typeof(NativeMethods.CATALOG_INFO)) };
            if (!NativeMethods.CryptCATCatalogInfoFromContext(hCatInfo, ref info, 0))
            {
                NativeMethods.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                NativeMethods.CryptCATAdminReleaseContext(hCatAdmin, 0);
                return null;
            }

            string catPath = info.wszCatalogFile;
            NativeMethods.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            NativeMethods.CryptCATAdminReleaseContext(hCatAdmin, 0);

            var guid = NativeMethods.WINTRUST_ACTION_GENERIC_VERIFY_V2;
            var fileInfo = new NativeMethods.WINTRUST_FILE_INFO
            {
                cbStruct = Marshal.SizeOf(typeof(NativeMethods.WINTRUST_FILE_INFO)),
                pcwszFilePath = catPath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };
            var data = new NativeMethods.WINTRUST_DATA
            {
                cbStruct = Marshal.SizeOf(typeof(NativeMethods.WINTRUST_DATA)),
                dwUIChoice = NativeMethods.WTD_UI_NONE,
                fdwRevocationChecks = NativeMethods.WTD_REVOKE_NONE,
                dwUnionChoice = NativeMethods.WTD_CHOICE_FILE,
                pFile = Marshal.AllocHGlobal(Marshal.SizeOf(fileInfo)),
                dwStateAction = NativeMethods.WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero
            };
            Marshal.StructureToPtr(fileInfo, data.pFile, false);

            long ret = NativeMethods.WinVerifyTrust(NativeMethods.INVALID_HANDLE_VALUE, ref guid, ref data);
            if (ret != 0) return null;

            IntPtr provData = NativeMethods.WTHelperProvDataFromStateData(data.hWVTStateData);
            if (provData == IntPtr.Zero) return null;
            IntPtr signer = NativeMethods.WTHelperGetProvSignerFromChain(provData, 0, false, 0);
            if (signer == IntPtr.Zero) return null;

            var sgnr = Marshal.PtrToStructure<NativeMethods.CRYPT_PROVIDER_SGNR>(signer);
            if (sgnr.csCertChain == 0) return null;
            var certCtx = Marshal.PtrToStructure<NativeMethods.CRYPT_PROVIDER_CERT>(sgnr.pasCertChain).pCert;
            if (certCtx == IntPtr.Zero) return null;

            var cert = new X509Certificate2(certCtx);
            byte[] sha256 = SHA256.Create().ComputeHash(cert.RawData);
            string result = BitConverter.ToString(sha256).Replace("-", "");

            data.dwStateAction = NativeMethods.WTD_STATEACTION_CLOSE;
            NativeMethods.WinVerifyTrust(NativeMethods.INVALID_HANDLE_VALUE, ref guid, ref data);
            Marshal.FreeHGlobal(data.pFile);

            return result;
        }

        private static class NativeMethods
        {
            public const uint GENERIC_READ = 0x80000000;
            public const uint FILE_SHARE_READ = 1;
            public const uint OPEN_EXISTING = 3;
            public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
            public const uint WTD_UI_NONE = 2;
            public const uint WTD_REVOKE_NONE = 0;
            public const uint WTD_CHOICE_FILE = 1;
            public const uint WTD_STATEACTION_VERIFY = 1;
            public const uint WTD_STATEACTION_CLOSE = 2;
            public static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool CloseHandle(IntPtr hObject);

            [DllImport("wintrust.dll", SetLastError = true)]
            public static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref int pcbHash, byte[]? pbHash, int dwFlags);

            [DllImport("wintrust.dll", SetLastError = true)]
            public static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, IntPtr pgSubsystem, int dwFlags);

            [DllImport("wintrust.dll", SetLastError = true)]
            public static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, int cbHash, int dwFlags, IntPtr phPrevCatInfo);

            [DllImport("wintrust.dll", SetLastError = true)]
            public static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, int dwFlags);

            [DllImport("wintrust.dll", SetLastError = true)]
            public static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, int dwFlags);

            [DllImport("wintrust.dll", SetLastError = true)]
            public static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, int dwFlags);

            public static extern long WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

            [DllImport("wintrust.dll", SetLastError = true)]
            public static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

            [DllImport("wintrust.dll", SetLastError = true)]
            public static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr pProvData, int idxSigner, bool fCounterSigner, int idxCounterSigner);

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct CATALOG_INFO { public int cbStruct; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile; }

            [StructLayout(LayoutKind.Sequential)]
            public struct WINTRUST_FILE_INFO
            {
                public int cbStruct;
                [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
                public IntPtr hFile;
                public IntPtr pgKnownSubject;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct WINTRUST_DATA
            {
                public int cbStruct;
                public IntPtr pPolicyCallbackData;
                public IntPtr pSIPClientData;
                public uint dwUIChoice;
                public uint fdwRevocationChecks;
                public uint dwUnionChoice;
                public IntPtr pFile;
                public uint dwStateAction;
                public IntPtr hWVTStateData;
                public IntPtr pwszURLReference;
                public uint dwProvFlags;
                public uint dwUIContext;
                public IntPtr pSignatureSettings;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct CRYPT_PROVIDER_SGNR { public int cbStruct; public long sftVerifyAsOf; public int csCertChain; public IntPtr pasCertChain; public int dwSignerType; public IntPtr psSigner; public int dwError; public int csCounterSigners; public IntPtr pasCounterSigners; public IntPtr pChainContext; }

            [StructLayout(LayoutKind.Sequential)]
            public struct CRYPT_PROVIDER_CERT { public int cbStruct; public IntPtr pCert; public int dwCertChoice; public IntPtr pCertStruct; public int dwFlags; public int dwError; }
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