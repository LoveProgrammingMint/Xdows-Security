using PeNet;

namespace Xdows_Local
{
    public static class Core
    {
        public record PEInfo
        {
            public String[]? ImportsDll;
            public String[]? ImportsName;
            public String[]? ExportsName;
        }

        public static String ScanAsync(String path, Boolean deep, Boolean extraData)
        {
            if (!File.Exists(path)) return String.Empty;

            if (!PeFile.IsPeFile(path))
            {
                try
                {
                    Byte[] fileContent = File.ReadAllBytes(path);
                    (Int32 score, String extra) scriptScanResult = ScriptScan.ScanScriptFile(path, fileContent);
                    if (scriptScanResult.score >= 100)
                    {
                        return extraData ? $"Xdows.script.code{scriptScanResult.score} {scriptScanResult.extra}" : $"Xdows.script.code{scriptScanResult.score}";
                    }
                    return String.Empty;
                }
                catch
                {
                    return String.Empty;
                }
            }

            PeFile peFile = new(path);
            PEInfo fileInfo = new();

            if (peFile.IsDll)
            {
                IReadOnlyList<PeNet.Header.Pe.ExportFunction>? exports = peFile.ExportedFunctions;
                if (exports != null)
                {
                    fileInfo.ExportsName = [.. exports.Select(exported => exported.Name ?? String.Empty)];
                }
                else
                {
                    fileInfo.ExportsName = [];
                }
            }

            IReadOnlyList<PeNet.Header.Pe.ImportFunction>? importedFunctions = peFile.ImportedFunctions;
            if (importedFunctions != null)
            {
                List<PeNet.Header.Pe.ImportFunction> validImports = importedFunctions
                    .Where(import => import.Name != null)
                    .ToList();

                fileInfo.ImportsDll = [.. validImports.Select(import => import.DLL)];
                fileInfo.ImportsName = [.. validImports.Select(import => import.Name ?? String.Empty)];
            }
            else
            {
                fileInfo.ImportsDll = [];
                fileInfo.ImportsName = [];
            }

            (Int32 score, String extra) score = Heuristic.Evaluate(path, peFile, fileInfo, deep);
            if (score.score >= 100)
            {
                return extraData ? $"Xdows.local.code{score.score} {score.extra}" : $"Xdows.local.code{score.score}";
            }

            return String.Empty;
        }
    }
}
