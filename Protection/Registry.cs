using Microsoft.Win32;
using System.Diagnostics;
using System.Security.Principal;
using static Protection.CallBack;

#pragma warning disable CA1416 // 验证平台兼容性

namespace Protection
{
    public class RegistryProtection : IProtectionModel
    {
        private static bool _isEnabled;
        private static Thread? _monitorThread;
        private static readonly Lock _lock = new();
        private static readonly HashSet<string> _whitelist = new(StringComparer.OrdinalIgnoreCase);
        private static InterceptCallBack? _interceptCallBack;
        private static readonly string _configDirectory;
        private static readonly string _logFile;
        public string Name => "RegistryProtection";
        // 关键监控路径
        private static readonly string[] _criticalPaths =
        [
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SYSTEM\CurrentControlSet\Services",
            @"SOFTWARE\Classes\exefile\shell\open\command",
            @"SOFTWARE\Classes\batfile\shell\open\command"
        ];

        // 恶意特征
        private static readonly string[] _maliciousPatterns =
        [
            "cmd.exe /c",
            "powershell.exe -enc",
            "powershell.exe -e ",
            "rundll32.exe javascript",
            "mshta.exe http",
            "certutil.exe -decode",
            "bitsadmin.exe /transfer",
            "regsvr32.exe /s",
            "schtasks.exe /create"
        ];

        static RegistryProtection()
        {
            _configDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config");
            _logFile = Path.Combine(_configDirectory, "registry_protection.log");
            Directory.CreateDirectory(_configDirectory);
            LoadConfiguration();
        }

        public bool IsEnabled()
        {
            lock (_lock)
            {
                return _isEnabled;
            }
        }

        public bool Enable(InterceptCallBack interceptCallBack)
        {
            lock (_lock)
            {
                if (_isEnabled) return true;

                try
                {
                    if (!IsAdministrator())
                    {
                        LogEvent("❌ 需要管理员权限");
                        return false;
                    }

                    _interceptCallBack = interceptCallBack;
                    _isEnabled = true;

                    _monitorThread = new Thread(MonitorRegistry)
                    {
                        IsBackground = true,
                        Name = "RegistryMonitor"
                    };
                    _monitorThread.Start();

                    LogEvent("✅ 注册表防护已启用");
                    return true;
                }
                catch (Exception ex)
                {
                    LogEvent($"❌ 启用失败: {ex.Message}");
                    _isEnabled = false;
                    return false;
                }
            }
        }

        public bool Disable()
        {
            lock (_lock)
            {
                if (!_isEnabled) return true;

                try
                {
                    _isEnabled = false;
                    _monitorThread?.Join(1000);
                    LogEvent("⏹️ 注册表防护已禁用");
                    return true;
                }
                catch (Exception ex)
                {
                    LogEvent($"⚠️ 禁用错误: {ex.Message}");
                    return false;
                }
            }
        }

        private static bool IsAdministrator()
        {
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private static void MonitorRegistry()
        {
            // 创建初始快照
            var lastSnapshot = CreateRegistrySnapshot();

            while (_isEnabled)
            {
                try
                {
                    Thread.Sleep(300); // 300ms检查间隔，更灵敏

                    var currentSnapshot = CreateRegistrySnapshot();
                    var changes = CompareSnapshots(lastSnapshot, currentSnapshot);

                    foreach (var change in changes)
                    {
                        if (_isEnabled) // 再次确认状态
                        {
                            ProcessChange(change);
                            // 更新快照
                            lastSnapshot = CreateRegistrySnapshot();
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogEvent($"监控错误: {ex.Message}");
                    Thread.Sleep(1000);
                }
            }
        }

        private static Dictionary<string, Dictionary<string, object>> CreateRegistrySnapshot()
        {
            var snapshot = new Dictionary<string, Dictionary<string, object>>();

            foreach (var path in _criticalPaths)
            {
                try
                {
                    // 读取64位视图
                    var values64 = ReadRegistryValues(RegistryView.Registry64, path);
                    if (values64 != null)
                    {
                        snapshot[$"HKEY_LOCAL_MACHINE\\{path}"] = values64;
                    }

                    // 读取32位视图（64位系统）
                    if (Environment.Is64BitOperatingSystem)
                    {
                        var values32 = ReadRegistryValues(RegistryView.Registry32, path);
                        if (values32 != null)
                        {
                            snapshot[$"HKEY_LOCAL_MACHINE_32\\{path}"] = values32;
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogEvent($"读取快照失败 {path}: {ex.Message}");
                }
            }

            return snapshot;
        }

        private static Dictionary<string, object>? ReadRegistryValues(RegistryView view, string subKeyPath)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var key = baseKey.OpenSubKey(subKeyPath, false); // 只读
                if (key == null) return null;

                var values = new Dictionary<string, object>();
                foreach (var valueName in key.GetValueNames())
                {
                    try
                    {
                        values[valueName] = key.GetValue(valueName) ?? "";
                    }
                    catch
                    {
                        // 忽略单个值读取错误
                    }
                }
                return values;
            }
            catch
            {
                return null;
            }
        }

        private static List<RegistryChange> CompareSnapshots(
            Dictionary<string, Dictionary<string, object>> oldSnapshot,
            Dictionary<string, Dictionary<string, object>> newSnapshot)
        {
            var changes = new List<RegistryChange>();
            var currentProcess = GetCurrentProcessInfo();

            // 检查新增或修改的值
            foreach (var newEntry in newSnapshot)
            {
                string registryPath = newEntry.Key;
                var newValues = newEntry.Value;

                if (!oldSnapshot.TryGetValue(registryPath, out Dictionary<string, object>? oldValues))
                {
                    // 全新注册表路径
                    foreach (var valuePair in newValues)
                    {
                        changes.Add(new RegistryChange
                        {
                            Path = registryPath,
                            ValueName = valuePair.Key,
                            OldValue = null,
                            NewValue = valuePair.Value,
                            ProcessName = currentProcess.Item1,
                            ProcessId = currentProcess.Item2
                        });
                    }
                }
                else
                {

                    // 检查新值或修改的值
                    foreach (var valuePair in newValues)
                    {
                        if (!oldValues.TryGetValue(valuePair.Key, out object? value))
                        {
                            // 新值
                            changes.Add(new RegistryChange
                            {
                                Path = registryPath,
                                ValueName = valuePair.Key,
                                OldValue = null,
                                NewValue = valuePair.Value,
                                ProcessName = currentProcess.Item1,
                                ProcessId = currentProcess.Item2
                            });
                        }
                        else if (!AreValuesEqual(value, valuePair.Value))
                        {
                            // 值被修改
                            changes.Add(new RegistryChange
                            {
                                Path = registryPath,
                                ValueName = valuePair.Key,
                                OldValue = value,
                                NewValue = valuePair.Value,
                                ProcessName = currentProcess.Item1,
                                ProcessId = currentProcess.Item2
                            });
                        }
                    }

                    // 检查被删除的值
                    foreach (var oldValuePair in oldValues)
                    {
                        if (!newValues.ContainsKey(oldValuePair.Key))
                        {
                            changes.Add(new RegistryChange
                            {
                                Path = registryPath,
                                ValueName = oldValuePair.Key,
                                OldValue = oldValuePair.Value,
                                NewValue = null,
                                ProcessName = currentProcess.Item1,
                                ProcessId = currentProcess.Item2
                            });
                        }
                    }
                }
            }

            return changes;
        }

        private static bool AreValuesEqual(object val1, object val2)
        {
            if (val1 == null && val2 == null) return true;
            if (val1 == null || val2 == null) return false;
            return val1.Equals(val2);
        }

        private static void ProcessChange(RegistryChange change)
        {
            // 跳过白名单项
            if (IsWhitelisted(change))
                return;

            // 检查是否为恶意值
            if (change.NewValue != null && IsMaliciousPattern(change.NewValue.ToString() ?? ""))
            {
                // 调用拦截回调 - 成功拦截
                _interceptCallBack?.Invoke(true, $"{change.Path}\\{change.ValueName}", "Reg");

                // 自动恢复原始值
                RestoreOriginalValue(change);
                LogThreat(change);
            }
            else if (change.NewValue == null && change.OldValue != null)
            {
                // 值被删除，也可能是恶意行为
                _interceptCallBack?.Invoke(true, change.Path, "Reg");
                RestoreOriginalValue(change);
                LogThreat(change);
            }
        }

        private static bool IsWhitelisted(RegistryChange change)
        {
            lock (_lock)
            {
                // 检查进程白名单
                if (_whitelist.Contains(change.ProcessName, StringComparer.OrdinalIgnoreCase))
                    return true;

                // 检查注册表路径白名单
                foreach (var whitelistItem in _whitelist)
                {
                    if (!string.IsNullOrEmpty(whitelistItem) &&
                        change.Path.Contains(whitelistItem, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }

                return false;
            }
        }

        private static bool IsMaliciousPattern(string value)
        {
            if (string.IsNullOrEmpty(value)) return false;
            value = value.ToLowerInvariant();
            return _maliciousPatterns.Any(pattern => value.Contains(pattern, StringComparison.InvariantCultureIgnoreCase));
        }

        private static void RestoreOriginalValue(RegistryChange change)
        {
            try
            {
                string actualPath = change.Path.Replace("HKEY_LOCAL_MACHINE_32\\", "").Replace("HKEY_LOCAL_MACHINE\\", "");
                RegistryView view = change.Path.Contains("HKEY_LOCAL_MACHINE_32") ? RegistryView.Registry32 : RegistryView.Registry64;
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var key = baseKey.OpenSubKey(actualPath, true);
                if (key != null)
                {
                    if (change.NewValue == null && change.OldValue != null)
                    {
                        // 恢复被删除的值
                        key.SetValue(change.ValueName, change.OldValue);
                    }
                    else if (change.OldValue == null)
                    {
                        // 删除新创建的恶意值
                        try
                        {
                            key.DeleteValue(change.ValueName, false);
                        }
                        catch
                        {
                            // 忽略删除错误
                        }
                    }
                    else
                    {
                        // 恢复原始值
                        key.SetValue(change.ValueName, change.OldValue);
                    }
                }
            }
            catch (Exception ex)
            {
                LogEvent($"恢复注册表值失败: {ex.Message}");
            }
        }

        private static (string, int) GetCurrentProcessInfo()
        {
            try
            {
                using var current = Process.GetCurrentProcess();
                return (current.ProcessName, current.Id);
            }
            catch
            {
                return ("unknown", 0);
            }
        }

        public static void LoadConfiguration()
        {
            lock (_lock)
            {
                _whitelist.Clear();
                var whitelistFile = Path.Combine(_configDirectory, "registry_whitelist.txt");
                if (File.Exists(whitelistFile))
                {
                    var lines = File.ReadAllLines(whitelistFile);
                    foreach (var line in lines)
                    {
                        var trimmed = line.Trim();
                        if (!string.IsNullOrEmpty(trimmed) && !trimmed.StartsWith('#'))
                        {
                            _whitelist.Add(trimmed);
                        }
                    }
                }
            }
        }

        public static void SaveConfiguration()
        {
            lock (_lock)
            {
                var whitelistFile = Path.Combine(_configDirectory, "registry_whitelist.txt");
                var lines = new List<string>
                {
                    "# 注册表防护白名单",
                    "# 每行一个进程名或注册表路径"
                };
                lines.AddRange(_whitelist);
                File.WriteAllLines(whitelistFile, lines);
            }
        }

        public static void AddToWhitelist(string pattern)
        {
            lock (_lock)
            {
                if (!_whitelist.Contains(pattern, StringComparer.OrdinalIgnoreCase))
                {
                    _whitelist.Add(pattern);
                    SaveConfiguration();
                }
            }
        }

        private static void LogEvent(string message)
        {
            try
            {
                File.AppendAllText(_logFile, $"[{DateTime.Now:HH:mm:ss.fff}] {message}{Environment.NewLine}");
            }
            catch
            {
                // 忽略日志错误
            }
        }

        private static void LogThreat(RegistryChange change)
        {
            var message = $"THREAT|{change.Path}|{change.ValueName}|{change.NewValue}|{change.ProcessName}";
            LogEvent(message);
        }

        private class RegistryChange
        {
            public string Path { get; set; } = string.Empty;
            public string ValueName { get; set; } = string.Empty;
            public object? OldValue { get; set; }
            public object? NewValue { get; set; }
            public string ProcessName { get; set; } = string.Empty;
            public int ProcessId { get; set; }
        }
    }
}