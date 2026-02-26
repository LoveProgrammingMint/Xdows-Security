namespace ScanEngine
{
    /// <summary>
    /// Wrapper around the SouXiao heuristic engine for file scanning.
    /// </summary>
    public class SouXiaoEngineScan
    {
        private readonly Boolean IsDebug = true;
        private readonly SouXiao.EngineEntry SouXiaoCoreV2026 = new();

        /// <summary>
        /// Initializes the SouXiao engine. Must be called before <see cref="ScanFile"/>.
        /// </summary>
        /// <returns><c>true</c> if initialization succeeded; otherwise <c>false</c>.</returns>
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

        /// <summary>
        /// Scans a file using the SouXiao heuristic engine.
        /// </summary>
        /// <param name="path">Absolute path to the file to scan.</param>
        /// <returns>A tuple indicating whether the file is a virus and the detection result name.</returns>
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
                        if (!(item1 == EngineResult.Safe || item1 == EngineResult.UnSupport))
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
