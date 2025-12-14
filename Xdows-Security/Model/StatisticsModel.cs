namespace Xdows_Security.Model
{
    public record StatisticsModel
    {
        public int ScansQuantity => Statistics.ScansQuantity;
        public int VirusQuantity => Statistics.VirusQuantity;
    }
}