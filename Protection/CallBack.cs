using static Protection.CallBack;

namespace Protection
{
    public static class CallBack
    {
        public delegate void InterceptCallBack(bool isSucceed, string path, string type);
    }
    public interface IETWProtectionModel
    {
        string Name { get; }
        bool Stop() { return false; }
        bool Run(InterceptCallBack interceptCallBack) { return false; }
        bool IsRun() { return false; }
    }
}
