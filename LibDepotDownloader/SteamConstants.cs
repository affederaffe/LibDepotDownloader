namespace LibDepotDownloader
{
    public static class SteamConstants
    {
        public const uint InvalidAppId = uint.MaxValue;
        public const uint InvalidDepotId = uint.MaxValue;
        public const ulong InvalidManifestId = ulong.MaxValue;
        public const string DefaultBranch = "public";

        internal const string DefaultDownloadDir = "depots";
        internal const string ConfigDir = ".DepotDownloader";
        internal const string StagingDir = ConfigDir + "/staging";
    }
}
