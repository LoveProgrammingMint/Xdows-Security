using Compatibility.Windows.Storage;
namespace Xdows_Security.Model
{
    public class ProtectionModel
    {
        public bool IsProtected => ProtectionStatus.IsOpen();
        public string LastScanTime
        {
            get => ApplicationData.Current.LocalSettings.Values["LastScanTime"] as string ?? "";
            set => ApplicationData.Current.LocalSettings.Values["LastScanTime"] = value;
        }
        public int ThreatCount
        {
            get => (int)(ApplicationData.Current.LocalSettings.Values["ThreatCount"] ?? 0);
            set => ApplicationData.Current.LocalSettings.Values["ThreatCount"] = value;
        }
    }
}