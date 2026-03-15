namespace Xdows_Local_Caller
{
    internal class Program
    {

        private static async Task<int> Main(string[] args)
        {
            Console.WriteLine("Xdows Local 调用器 By Shiyi\n");

            if (args.Length == 0)
            {
                Console.WriteLine("用法: <本程序路径> <文件路径> [-d]");
                Console.WriteLine("  -d 代表启用深度扫描");
                return 1;
            }

            string path = args[0];
            bool deep = args.Contains("-d") || args.Contains("--deep");

            if (path.StartsWith('\"') && path.EndsWith('\"'))
            {
                path = path.Trim('"');
            }

            await RunScanAsync(path, deep);
            return 0;
        }


        private static async Task RunScanAsync(string path, bool deep)
        {
            if (!File.Exists(path) && !Directory.Exists(path))
            {
                Console.Error.WriteLine($"错误: 路径不存在 - {path}");
                Environment.Exit(1);
                return;
            }

            Console.WriteLine($"开始扫描: {path}");
            Console.WriteLine($"深度模式: {(deep ? "开启" : "关闭")}");

            try
            {
                var result = Xdows_Local.Core.ScanAsync(path, deep, true);
                if (result == String.Empty)
                {
                    Console.WriteLine("Is Safe");

                }
                else
                {
                    Console.WriteLine(result);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"扫描发生异常: {ex.Message}");
                Environment.Exit(1);
            }
        }
    }
}