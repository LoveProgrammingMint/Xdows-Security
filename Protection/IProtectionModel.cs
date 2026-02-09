using static Protection.CallBack;

namespace Protection
{
    public interface IProtectionModel
    {
        string Name { get; }
        bool Disable() { return false; }
        bool Enable(InterceptCallBack toastCallBack) { return false; }
        bool IsEnabled() { return false; }
    }
}
