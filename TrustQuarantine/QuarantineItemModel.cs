namespace TrustQuarantine
{
    public class QuarantineItemModel
    {
        public string FileHash { get; set; } = string.Empty;
        public byte[] FileData { get; set; } = [];
        public string SourcePath { get; set; } = string.Empty;
        public string ThreatName { get; set; } = string.Empty;
        public string EncryptionKey { get; set; } = string.Empty;
        public string IV { get; set; } = string.Empty;
    }
}
