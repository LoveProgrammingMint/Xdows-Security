using PublicPart;

namespace Helper
{
    public class SouXiaoEngineScan
    {
        private readonly Boolean IsDebug = true;
        private readonly SouXiao.EngineEntry SouXiaoCoreV2026 = new();
        public bool Initialize()
        {
            try
            {
                return SouXiaoCoreV2026.Initialize();
            }
            catch (Exception)
            {
                if (IsDebug) { throw; }
                return false;
            }
        }
        public (bool IsVirus, string Result) ScanFile(string path)
        {
            try
            {
                if (SouXiaoCoreV2026 == null)
                {
                    throw new InvalidOperationException("SouXiaoCore is not initialized.");
                }
                var scanResult = SouXiaoCoreV2026.Scan(path);
                foreach (var item in scanResult)
                {
                    foreach (var item1 in item.Value)
                    {
                        if (item1 is not (EngineResult.Safe or EngineResult.UnSupport))
                        {
                            return (true, $"SouXiao.Heuristic.{item.Key}");
                        }
                    }
                }
                return (false, string.Empty);
            }
            catch (Exception)
            {
                if (IsDebug) { throw; }

                return (false, string.Empty);
            }
        }
    }
}
