namespace Test
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var test = new Protection.ETW.ProcessProtection();
            test.Run();// 原来是这么用的！
        }
    }
}
