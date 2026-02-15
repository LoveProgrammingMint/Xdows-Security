namespace TrustQuarantine
{
    public class TrustItemModel
    {
        public string Path { get; set; }
        public string Hash { get; set; }

        public TrustItemModel(string path, string hash)
        {
            Path = path;
            Hash = hash;
        }
    }
}
