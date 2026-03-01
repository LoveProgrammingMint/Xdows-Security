using System.Text;
using System.Text.RegularExpressions;

namespace Xdows_Local
{
    public static class ScriptScan
    {
        public static (Int32 score, String extra) ScanScriptFile(String filePath, Byte[] fileContent)
        {
            try
            {
                var nativeResult = Native_ScriptScanner.ScanScriptFileManaged(filePath, fileContent);
                if (nativeResult.score > 0)
                {
                    return nativeResult;
                }
            }
            catch
            {
            }

            return ScanScriptFileManaged(filePath, fileContent);
        }

        private static (Int32 score, String extra) ScanScriptFileManaged(String filePath, Byte[] fileContent)
        {
            Int32 score = 0;
            List<String> extra = [];
            String fileExtension = GetExtString(filePath);

            if (IsSuspiciousBat(fileContent))
            {
                score += 10;
                extra.Add("CamouflageBat");
            }

            if (fileExtension == ".lnk")
            {
                (Int32 score, String extra) lnkResult = CheckShortcutFile(filePath, fileContent);
                score += lnkResult.score;
                if (!String.IsNullOrEmpty(lnkResult.extra))
                    extra.Add(lnkResult.extra);
            }
            else if (IsScriptFile(fileExtension))
            {
                (Int32 score, String extra) scriptResult = CheckScriptFile(fileExtension, fileContent);
                score += scriptResult.score;
                if (!String.IsNullOrEmpty(scriptResult.extra))
                    extra.Add(scriptResult.extra);
            }

            return (score, String.Join(" ", extra));
        }

        private static unsafe String GetExtString(String path)
        {
            if (String.IsNullOrEmpty(path)) return String.Empty;

            fixed (Char* p = path)
            {
                Char* dot = null, slash = p;
                for (Char* c = p + path.Length - 1; c >= p; c--)
                {
                    if (*c == '.') { dot = c; break; }
                    if (*c is '\\' or '/') slash = c;
                }
                if (dot == null || dot < slash) return String.Empty;

                Int32 len = (Int32)(p + path.Length - dot);
                Span<Char> buf = stackalloc Char[len];
                ReadOnlySpan<Char> src = new(dot, len);
                src.ToLowerInvariant(buf);
                return buf.ToString();
            }
        }

        private static Boolean IsSuspiciousBat(Byte[] fileContent)
        {
            if (fileContent.Length == 0) return false;
            ReadOnlySpan<Byte> data = fileContent.AsSpan();

            if (data.IndexOf("program cannot be run in"u8) >= 0) return true;
            if (data.IndexOf("LoadLibraryA"u8) >= 0) return true;
            if (data.IndexOf("Win32"u8) >= 0) return true;
            if (data.IndexOf("kernel32.dll"u8) >= 0) return true;
            if (data.IndexOf("ntdll.dll"u8) >= 0) return true;
            if (data.IndexOf("GetProcAddress"u8) >= 0) return true;
            if (data.IndexOf(@"C:\windows\"u8) >= 0) return true;
            if (data.IndexOf("*.exe"u8) >= 0) return true;
            if (data.IndexOf("Shutdown"u8) >= 0) return true;

            return false;
        }

        private static (Int32 score, String extra) CheckShortcutFile(String filePath, Byte[] fileContent)
        {
            Int32 score = 0;
            List<String> extra = [];

            try
            {
                if (fileContent.Length > 1024 * 10)
                {
                    score += 10;
                    extra.Add("LargeShortcut");
                }

                String content = Encoding.ASCII.GetString(fileContent);

                if (content.Contains(".exe") &&
                    (!content.Contains("System32", StringComparison.OrdinalIgnoreCase) &&
                     !content.Contains("Program Files", StringComparison.OrdinalIgnoreCase)))
                {
                    score += 15;
                    extra.Add("SuspiciousTarget");
                }

                if (content.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("wscript.exe", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("cscript.exe", StringComparison.OrdinalIgnoreCase))
                {
                    score += 20;
                    extra.Add("ScriptInShortcut");
                }

                if (content.Contains("-windowstyle hidden", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("-w hidden", StringComparison.OrdinalIgnoreCase))
                {
                    score += 15;
                    extra.Add("HiddenExecution");
                }

                if (content.Contains("base64", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("FromBase64String", StringComparison.OrdinalIgnoreCase))
                {
                    score += 25;
                    extra.Add("EncodedContent");
                }

                if (content.Contains("download", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("invoke-webrequest", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("wget", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("curl", StringComparison.OrdinalIgnoreCase))
                {
                    score += 20;
                    extra.Add("DownloadBehavior");
                }
            }
            catch
            {
                score += 10;
                extra.Add("CorruptedShortcut");
            }

            return (score, String.Join(" ", extra));
        }

        private static (Int32 score, String extra) CheckScriptFile(String extension, Byte[] fileContent)
        {
            Int32 score = 0;
            List<String> extra = [];

            try
            {
                String content = Encoding.UTF8.GetString(fileContent);

                score += CheckGenericScript(content, extra);

                score += extension switch
                {
                    ".ps1" or ".psm1" or ".psd1" => CheckPowerShellScript(content, extra),
                    ".vbs" or ".vbe" => CheckVBScript(content, extra),
                    ".js" or ".jse" => CheckJavaScript(content, extra),
                    ".bat" or ".cmd" => CheckBatchScript(content, extra),
                    ".py" or ".pyw" => CheckPythonScript(content, extra),
                    ".sh" => CheckShellScript(content, extra),
                    _ => 0
                };
            }
            catch
            {
                score += 10;
                extra.Add("CorruptedScript");
            }

            return (score, String.Join(" ", extra));
        }

        private static Int32 CheckGenericScript(String content, List<String> extra)
        {
            Int32 score = 0;

            if (content.Contains("eval(") || content.Contains("Invoke-Expression") ||
                content.Contains("Execute(") || content.Contains("exec("))
            {
                score += 20;
                extra.Add("DynamicExecution");
            }

            if (content.Contains("base64") || content.Contains("FromBase64String") ||
                content.Contains("atob") || content.Contains("btoa"))
            {
                score += 15;
                extra.Add("EncodedContent");
            }

            if (Regex.IsMatch(content, @"(download|wget|curl|invoke-webrequest|fetch\s*\()", RegexOptions.IgnoreCase))
            {
                score += 20;
                extra.Add("DownloadBehavior");
            }

            if (Regex.IsMatch(content, @"(http|https|ftp)://", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("NetworkActivity");
            }

            if (Regex.IsMatch(content, @"(delete|remove|copy|move|create\s+file|write\s+file)", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("FileOperation");
            }

            if (Regex.IsMatch(content, @"(reg\s+|registry|regedit|reg.exe)", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("RegistryOperation");
            }

            if (Regex.IsMatch(content, @"(start-process|createobject|wscript.shell|shell.application)", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("ProcessOperation");
            }

            if (Regex.IsMatch(content, @"(startup|runonce|autorun|msconfig)", RegexOptions.IgnoreCase))
            {
                score += 20;
                extra.Add("PersistenceMechanism");
            }

            if (Regex.IsMatch(content, @"(nyancat|rainbow|memz|trollface)", RegexOptions.IgnoreCase))
            {
                score += 30;
                extra.Add("MEMZSignature");
            }

            if (Regex.IsMatch(content, @"(delete\s+.*system|format\s+|shutdown|reboot|blue\s+screen)", RegexOptions.IgnoreCase))
            {
                score += 25;
                extra.Add("SystemDestruction");
            }

            return score;
        }

        private static Int32 CheckPowerShellScript(String content, List<String> extra)
        {
            Int32 score = 0;

            if (Regex.IsMatch(content, @"-executionpolicy\s+bypass", RegexOptions.IgnoreCase))
            {
                score += 20;
                extra.Add("BypassExecutionPolicy");
            }

            if (Regex.IsMatch(content, @"-windowstyle\s+hidden", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("HiddenWindow");
            }

            if (Regex.IsMatch(content, @"(reflection|assembly.load|loadfrom)", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("ReflectionUsage");
            }

            if (Regex.IsMatch(content, @"(add-type|dllimport|getmodulehandle)", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("WinAPIUsage");
            }

            if (Regex.IsMatch(content, @"new-object\s+-comobject", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("COMObjectUsage");
            }

            return score;
        }

        private static Int32 CheckVBScript(String content, List<String> extra)
        {
            Int32 score = 0;

            if (Regex.IsMatch(content, @"createobject\s*\(\s*""wscript.shell""", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("WScriptShellUsage");
            }

            if (Regex.IsMatch(content, @"createobject\s*\(\s*""scripting.filesystemobject""", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("FileSystemObjectUsage");
            }

            if (Regex.IsMatch(content, @"createobject\s*\(\s*""shell.application""", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("ShellApplicationUsage");
            }

            return score;
        }

        private static Int32 CheckJavaScript(String content, List<String> extra)
        {
            Int32 score = 0;

            if (Regex.IsMatch(content, @"new\s+activexobject", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("ActiveXObjectUsage");
            }

            if (Regex.IsMatch(content, @"wscript.", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("WScriptUsage");
            }

            return score;
        }

        private static Int32 CheckBatchScript(String content, List<String> extra)
        {
            Int32 score = 0;

            if (Regex.IsMatch(content, @"@echo\s+off", RegexOptions.IgnoreCase))
            {
                score += 5;
                extra.Add("HiddenCommands");
            }

            if (Regex.IsMatch(content, @"powershell\s+", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("PowerShellInBatch");
            }

            if (Regex.IsMatch(content, @"certutil\s+", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("CertutilUsage");
            }

            if (Regex.IsMatch(content, @"bitsadmin\s+", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("BitsadminUsage");
            }

            if (Regex.IsMatch(content, @"(del\s+[/sfq]|format\s+|rmdir\s+[/sq]|shutdown\s+[/sfr])", RegexOptions.IgnoreCase))
            {
                score += 25;
                extra.Add("SystemDestruction");
            }

            if (Regex.IsMatch(content, @"(reg\s+(add|delete)|regedit)", RegexOptions.IgnoreCase))
            {
                score += 20;
                extra.Add("RegistryModification");
            }

            return score;
        }

        private static Int32 CheckPythonScript(String content, List<String> extra)
        {
            Int32 score = 0;

            if (Regex.IsMatch(content, @"os.system\s*\(", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("OSSystemUsage");
            }

            if (Regex.IsMatch(content, @"subprocess.", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("SubprocessUsage");
            }

            if (Regex.IsMatch(content, @"urllib.", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("UrllibUsage");
            }

            if (Regex.IsMatch(content, @"requests.", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("RequestsUsage");
            }

            return score;
        }

        private static Int32 CheckShellScript(String content, List<String> extra)
        {
            Int32 score = 0;

            if (Regex.IsMatch(content, @"(wget|curl)\s+", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("DownloadTool");
            }

            if (Regex.IsMatch(content, @"chmod\s+", RegexOptions.IgnoreCase))
            {
                score += 5;
                extra.Add("ChmodUsage");
            }

            return score;
        }

        private static Boolean IsScriptFile(String extension)
        {
            String[] scriptExtensions = [
                ".ps1", ".psm1", ".psd1",
                ".vbs", ".vbe",
                ".js", ".jse",
                ".bat", ".cmd",
                ".py", ".pyw",
                ".sh", ".bash", ".zsh",
                ".pl", ".pm",
                ".rb",
                ".php", ".phtml", ".php3", ".php4", ".php5"
            ];

            return scriptExtensions.Contains(extension);
        }
    }
}
