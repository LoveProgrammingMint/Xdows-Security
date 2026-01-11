using static Protection.CallBack;

namespace Protection
{
    public interface IProtectionModel
    {
        string Name { get; }
        public bool Disable() { return false; }
        public bool Enable(InterceptCallBack toastCallBack) { return false; }
        public bool IsEnabled() { return false; }
    }
}
