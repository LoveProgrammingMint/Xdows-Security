using PeNet;

namespace Xdows_Local
{
    public static class Core
    {
        //public static string SignedAndValid = string.Empty;

        public record PEInfo
        {
            public string[]? ImportsDll;
            public string[]? ImportsName;
            public string[]? ExportsName;
        }
        public static string ScanAsync(string path, bool deep, bool ExtraData)
        {
            if (!File.Exists(path)) return string.Empty;

            if (!PeFile.IsPeFile(path))
            {
                try
                {
                    var fileContent = File.ReadAllBytes(path);
                    var scriptScanResult = ScriptScan.ScanScriptFile(path, fileContent);
                    if (scriptScanResult.score >= 100)
                    {
                        return ExtraData ? $"Xdows.script.code{scriptScanResult.score} {scriptScanResult.extra}" : $"Xdows.script.code{scriptScanResult.score}";
                    }
                    return string.Empty;
                }
                catch
                {
                    return string.Empty;
                }
            }

            var peFile = new PeFile(path);
            var fileInfo = new PEInfo();

            if (peFile.IsDll)
            {
                var exports = peFile.ExportedFunctions;
                if (exports != null)
                {
                    fileInfo.ExportsName = [.. exports.Select(exported => exported.Name ?? string.Empty)];
                }
                else
                {
                    fileInfo.ExportsName = [];
                }
            }
            var importedFunctions = peFile.ImportedFunctions;
            if (importedFunctions != null)
            {
                var validImports = importedFunctions
                    .Where(import => import.Name != null)
                    .ToList();

                fileInfo.ImportsDll = [.. validImports.Select(import => import.DLL)];
                fileInfo.ImportsName = [.. validImports.Select(import => import.Name ?? string.Empty)];
            }
            else
            {
                fileInfo.ImportsDll = [];
                fileInfo.ImportsName = [];
            }

            var score = Heuristic.Evaluate(path, peFile, fileInfo, deep);
            if (score.score >= 100)
            {
                return ExtraData ? $"Xdows.local.code{score.score} {score.extra}" : $"Xdows.local.code{score.score}";
            }
            return string.Empty;
        }
    }
}