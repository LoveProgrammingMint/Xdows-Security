using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Xdows.ScanEngine
{
    public static class ScriptScan
    {
        /// <summary>
        /// 扫描脚本文件和快捷方式文件，返回评分和额外信息
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <param name="fileContent">文件内容</param>
        /// <returns>评分和额外信息</returns>
        public static async Task<(int score, string extra)> ScanScriptFileAsync(string filePath, byte[] fileContent)
        {
            return await Task.Run(() =>
            {
                int score = 0;
                var extra = new List<string>();
                var fileExtension = GetExtString(filePath);
                if (IsSuspiciousBat(fileContent))
                {
                    score += 10;
                    extra.Add("CamouflageBat");
                }
                // 检查快捷方式文件
                if (fileExtension == ".lnk")
                {
                    var lnkResult = CheckShortcutFile(filePath, fileContent);
                    score += lnkResult.score;
                    if (!string.IsNullOrEmpty(lnkResult.extra))
                        extra.Add(lnkResult.extra);
                }
                // 检查脚本文件
                else if (IsScriptFile(fileExtension))
                {
                    var scriptResult = CheckScriptFile(fileExtension, fileContent);
                    score += scriptResult.score;
                    if (!string.IsNullOrEmpty(scriptResult.extra))
                        extra.Add(scriptResult.extra);
                }

                return (score, string.Join(" ", extra));
            }).ConfigureAwait(false);
        }
        unsafe static string GetExtString(string path)
        {
            if (string.IsNullOrEmpty(path)) return string.Empty;

            fixed (char* p = path)
            {
                char* dot = null, slash = p;
                for (char* c = p + path.Length - 1; c >= p; c--)
                {
                    if (*c == '.') { dot = c; break; }
                    if (*c == '\\' || *c == '/') slash = c;
                }
                if (dot == null || dot < slash) return string.Empty;

                int len = (int)(p + path.Length - dot);
                Span<char> buf = stackalloc char[len];
                ReadOnlySpan<char> src = new ReadOnlySpan<char>(dot, len);
                src.ToLowerInvariant(buf);
                return buf.ToString();
            }
        }
        private static bool IsSuspiciousBat(byte[] fileContent)
        {
            if (fileContent.Length == 0) return false;
            var data = fileContent.AsSpan();

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

        /// <summary>
        /// 检查快捷方式文件
        /// </summary>
        private static (int score, string extra) CheckShortcutFile(string filePath, byte[] fileContent)
        {
            int score = 0;
            var extra = new List<string>();

            try
            {
                // 检查文件大小是否异常
                if (fileContent.Length > 1024 * 10) // 大于10KB的快捷方式可能有问题
                {
                    score += 10;
                    extra.Add("LargeShortcut");
                }

                // 检查是否包含可疑内容
                var content = Encoding.ASCII.GetString(fileContent);
                
                // 检查是否指向系统目录外的可执行文件
                if (content.Contains(".exe") && 
                    (!content.Contains("System32", StringComparison.OrdinalIgnoreCase) && 
                     !content.Contains("Program Files", StringComparison.OrdinalIgnoreCase)))
                {
                    score += 15;
                    extra.Add("SuspiciousTarget");
                }

                // 检查是否包含可疑参数
                if (content.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("wscript.exe", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("cscript.exe", StringComparison.OrdinalIgnoreCase))
                {
                    score += 20;
                    extra.Add("ScriptInShortcut");
                }

                // 检查是否包含隐藏参数
                if (content.Contains("-windowstyle hidden", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("-w hidden", StringComparison.OrdinalIgnoreCase))
                {
                    score += 15;
                    extra.Add("HiddenExecution");
                }

                // 检查是否包含编码内容
                if (content.Contains("base64", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("FromBase64String", StringComparison.OrdinalIgnoreCase))
                {
                    score += 25;
                    extra.Add("EncodedContent");
                }

                // 检查是否包含下载行为
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
                // 解析失败，可能是异常的快捷方式文件
                score += 10;
                extra.Add("CorruptedShortcut");
            }

            return (score, string.Join(" ", extra));
        }

        /// <summary>
        /// 检查脚本文件
        /// </summary>
        private static (int score, string extra) CheckScriptFile(string extension, byte[] fileContent)
        {
            int score = 0;
            var extra = new List<string>();

            try
            {
                var content = Encoding.UTF8.GetString(fileContent);
                
                // 通用脚本检查
                score += CheckGenericScript(content, extra);

                // 根据脚本类型进行特定检查
                switch (extension)
                {
                    case ".ps1":
                    case ".psm1":
                    case ".psd1":
                        score += CheckPowerShellScript(content, extra);
                        break;
                    case ".vbs":
                    case ".vbe":
                        score += CheckVBScript(content, extra);
                        break;
                    case ".js":
                    case ".jse":
                        score += CheckJavaScript(content, extra);
                        break;
                    case ".bat":
                    case ".cmd":
                        score += CheckBatchScript(content, extra);
                        break;
                    case ".py":
                    case ".pyw":
                        score += CheckPythonScript(content, extra);
                        break;
                    case ".sh":
                        score += CheckShellScript(content, extra);
                        break;
                }
            }
            catch
            {
                // 解析失败，可能是异常的脚本文件
                score += 10;
                extra.Add("CorruptedScript");
            }

            return (score, string.Join(" ", extra));
        }

        /// <summary>
        /// 通用脚本检查
        /// </summary>
        private static int CheckGenericScript(string content, List<string> extra)
        {
            int score = 0;

            // 检查是否包含混淆代码
            if (content.Contains("eval(") || content.Contains("Invoke-Expression") || 
                content.Contains("Execute(") || content.Contains("exec("))
            {
                score += 20;
                extra.Add("DynamicExecution");
            }

            // 检查是否包含编码内容
            if (content.Contains("base64") || content.Contains("FromBase64String") || 
                content.Contains("atob") || content.Contains("btoa"))
            {
                score += 15;
                extra.Add("EncodedContent");
            }

            // 检查是否包含下载行为
            if (Regex.IsMatch(content, @"(download|wget|curl|invoke-webrequest|fetch\s*\()", RegexOptions.IgnoreCase))
            {
                score += 20;
                extra.Add("DownloadBehavior");
            }

            // 检查是否包含网络请求
            if (Regex.IsMatch(content, @"(http|https|ftp)://", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("NetworkActivity");
            }

            // 检查是否包含文件操作
            if (Regex.IsMatch(content, @"(delete|remove|copy|move|create\s+file|write\s+file)", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("FileOperation");
            }

            // 检查是否包含注册表操作
            if (Regex.IsMatch(content, @"(reg\s+|registry|regedit|reg\.exe)", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("RegistryOperation");
            }

            // 检查是否包含进程操作
            if (Regex.IsMatch(content, @"(start-process|createobject|wscript\.shell|shell\.application)", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("ProcessOperation");
            }

            // 检查是否包含自启动相关
            if (Regex.IsMatch(content, @"(startup|runonce|autorun|msconfig)", RegexOptions.IgnoreCase))
            {
                score += 20;
                extra.Add("PersistenceMechanism");
            }

            // 通用MEMZ病毒特征检测
            if (Regex.IsMatch(content, @"(nyancat|rainbow|memz|trollface)", RegexOptions.IgnoreCase))
            {
                score += 30;
                extra.Add("MEMZSignature");
            }

            // 检查是否包含系统破坏行为
            if (Regex.IsMatch(content, @"(delete\s+.*system|format\s+|shutdown|reboot|blue\s+screen)", RegexOptions.IgnoreCase))
            {
                score += 25;
                extra.Add("SystemDestruction");
            }

            // 检查是否包含大量弹窗
            if (Regex.Matches(content, @"(msgbox|alert|messagebox|showmessage)", RegexOptions.IgnoreCase).Count > 5)
            {
                score += 20;
                extra.Add("MultiplePopups");
            }

            // 检查是否包含鼠标移动或键盘干扰
            if (Regex.IsMatch(content, @"(mousemove|cursor|setcursorpos|blockinput|keyboard)", RegexOptions.IgnoreCase))
            {
                score += 20;
                extra.Add("InputInterference");
            }

            // 检查是否包含屏幕效果
            if (Regex.IsMatch(content, @"(screen|display|color\s+change|invert|fullscreen)", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("ScreenEffects");
            }

            // 检查是否包含音效
            if (Regex.IsMatch(content, @"(play\s+sound|beep|audio|\.wav|\.mp3)", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("AudioEffects");
            }

            // 检查是否包含自复制行为
            if (Regex.IsMatch(content, @"(copy\s+.*%.*%|self\s+replicate|spread)", RegexOptions.IgnoreCase))
            {
                score += 25;
                extra.Add("SelfReplication");
            }

            return score;
        }

        /// <summary>
        /// PowerShell脚本特定检查
        /// </summary>
        private static int CheckPowerShellScript(string content, List<string> extra)
        {
            int score = 0;

            // 检查是否绕过执行策略
            if (Regex.IsMatch(content, @"-executionpolicy\s+bypass", RegexOptions.IgnoreCase))
            {
                score += 20;
                extra.Add("BypassExecutionPolicy");
            }

            // 检查是否隐藏窗口
            if (Regex.IsMatch(content, @"-windowstyle\s+hidden", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("HiddenWindow");
            }

            // 检查是否使用反射
            if (Regex.IsMatch(content, @"(reflection|assembly\.load|loadfrom)", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("ReflectionUsage");
            }

            // 检查是否使用Windows API
            if (Regex.IsMatch(content, @"(add-type|dllimport|getmodulehandle)", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("WinAPIUsage");
            }

            // 检查是否使用COM对象
            if (Regex.IsMatch(content, @"new-object\s+-comobject", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("COMObjectUsage");
            }

            return score;
        }

        /// <summary>
        /// VBScript特定检查
        /// </summary>
        private static int CheckVBScript(string content, List<string> extra)
        {
            int score = 0;

            // 检查是否使用WScript.Shell
            if (Regex.IsMatch(content, @"createobject\s*\(\s*""wscript\.shell""", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("WScriptShellUsage");
            }

            // 检查是否使用FileSystemObject
            if (Regex.IsMatch(content, @"createobject\s*\(\s*""scripting\.filesystemobject""", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("FileSystemObjectUsage");
            }

            // 检查是否使用Shell.Application
            if (Regex.IsMatch(content, @"createobject\s*\(\s*""shell\.application""", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("ShellApplicationUsage");
            }

            // 检查是否使用ScriptControl
            if (Regex.IsMatch(content, @"createobject\s*\(\s*""msscriptcontrol\.scriptcontrol""", RegexOptions.IgnoreCase))
            {
                score += 20;
                extra.Add("ScriptControlUsage");
            }

            return score;
        }

        /// <summary>
        /// JavaScript特定检查
        /// </summary>
        private static int CheckJavaScript(string content, List<string> extra)
        {
            int score = 0;

            // 检查是否使用ActiveXObject
            if (Regex.IsMatch(content, @"new\s+activexobject", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("ActiveXObjectUsage");
            }

            // 检查是否使用WScript
            if (Regex.IsMatch(content, @"wscript\.", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("WScriptUsage");
            }

            // 检查是否使用Shell对象
            if (Regex.IsMatch(content, @"shell\.application", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("ShellApplicationUsage");
            }

            return score;
        }

        /// <summary>
        /// 批处理脚本特定检查
        /// </summary>
        private static int CheckBatchScript(string content, List<string> extra)
        {
            int score = 0;

            // 检查是否隐藏命令窗口
            if (Regex.IsMatch(content, @"@echo\s+off", RegexOptions.IgnoreCase))
            {
                score += 5;
                extra.Add("HiddenCommands");
            }

            // 检查是否使用PowerShell
            if (Regex.IsMatch(content, @"powershell\s+", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("PowerShellInBatch");
            }

            // 检查是否使用certutil
            if (Regex.IsMatch(content, @"certutil\s+", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("CertutilUsage");
            }

            // 检查是否使用bitsadmin
            if (Regex.IsMatch(content, @"bitsadmin\s+", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("BitsadminUsage");
            }

            // MEMZ病毒特征检测 - 彩虹猫相关内容
            if (Regex.IsMatch(content, @"(nyancat|rainbow|memz|trollface)", RegexOptions.IgnoreCase))
            {
                score += 30;
                extra.Add("MEMZSignature");
            }

            // 检查是否包含系统破坏行为
            if (Regex.IsMatch(content, @"(del\s+\/[sfq]|format\s+|rmdir\s+\/[sq]|shutdown\s+\/[sfr])", RegexOptions.IgnoreCase))
            {
                score += 25;
                extra.Add("SystemDestruction");
            }

            // 检查是否修改注册表
            if (Regex.IsMatch(content, @"(reg\s+(add|delete)|regedit)", RegexOptions.IgnoreCase))
            {
                score += 20;
                extra.Add("RegistryModification");
            }

            // 检查是否创建自启动项
            if (Regex.IsMatch(content, @"(copy\s+.*%allusersprofile%.*startup|copy\s+.*%appdata%.*microsoft\\windows\\start\s+menu\\programs\\startup)", RegexOptions.IgnoreCase))
            {
                score += 25;
                extra.Add("StartupPersistence");
            }

            // 检查是否修改系统文件
            if (Regex.IsMatch(content, @"(copy\s+.*%windir%\\system32|attrib\s+.*\+h\s+.*%windir%\\system32)", RegexOptions.IgnoreCase))
            {
                score += 30;
                extra.Add("SystemFileModification");
            }

            // 检查是否创建多个批处理文件
            if (Regex.Matches(content, @"echo\s+.*>>.*\.bat", RegexOptions.IgnoreCase).Count > 3)
            {
                score += 20;
                extra.Add("MultipleBatchCreation");
            }

            // 检查是否包含错误消息弹窗
            if (Regex.IsMatch(content, @"(msg\s+\*\s|errorlevel|error)", RegexOptions.IgnoreCase))
            {
                score += 15;
                extra.Add("ErrorMessagePopup");
            }

            // 检查是否包含鼠标移动或键盘干扰
            if (Regex.IsMatch(content, @"(mousemove|setmousepos|blockinput)", RegexOptions.IgnoreCase))
            {
                score += 20;
                extra.Add("InputInterference");
            }

            // 检查是否包含屏幕效果
            if (Regex.IsMatch(content, @"(color\s+[0-9a-f]|mode\s+con|cls)", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("ScreenEffects");
            }

            // 检查是否包含音效
            if (Regex.IsMatch(content, @"(start\s+.*\.wav|start\s+.*\.mp3|echo\s+\007)", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("AudioEffects");
            }

            return score;
        }

        /// <summary>
        /// Python脚本特定检查
        /// </summary>
        private static int CheckPythonScript(string content, List<string> extra)
        {
            int score = 0;

            // 检查是否使用os.system
            if (Regex.IsMatch(content, @"os\.system\s*\(", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("OSSystemUsage");
            }

            // 检查是否使用subprocess
            if (Regex.IsMatch(content, @"subprocess\.", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("SubprocessUsage");
            }

            // 检查是否使用urllib
            if (Regex.IsMatch(content, @"urllib\.", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("UrllibUsage");
            }

            // 检查是否使用requests
            if (Regex.IsMatch(content, @"requests\.", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("RequestsUsage");
            }

            return score;
        }

        /// <summary>
        /// Shell脚本特定检查
        /// </summary>
        private static int CheckShellScript(string content, List<string> extra)
        {
            int score = 0;

            // 检查是否使用wget或curl
            if (Regex.IsMatch(content, @"(wget|curl)\s+", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("DownloadTool");
            }

            // 检查是否使用chmod
            if (Regex.IsMatch(content, @"chmod\s+", RegexOptions.IgnoreCase))
            {
                score += 5;
                extra.Add("ChmodUsage");
            }

            // 检查是否使用systemctl
            if (Regex.IsMatch(content, @"systemctl\s+", RegexOptions.IgnoreCase))
            {
                score += 10;
                extra.Add("SystemctlUsage");
            }

            return score;
        }

        /// <summary>
        /// 判断是否为脚本文件
        /// </summary>
        private static bool IsScriptFile(string extension)
        {
            string[] scriptExtensions = {
                ".ps1", ".psm1", ".psd1",  // PowerShell
                ".vbs", ".vbe",            // VBScript
                ".js", ".jse",              // JavaScript
                ".bat", ".cmd",             // Batch
                ".py", ".pyw",              // Python
                ".sh", ".bash", ".zsh",     // Shell
                ".pl", ".pm",               // Perl
                ".rb",                      // Ruby
                ".php", ".phtml", ".php3", ".php4", ".php5"  // PHP
            };

            return scriptExtensions.Contains(extension);
        }
    }
}