namespace LibDepotDownloader
{
    public record DepotDownloadInfo(uint Id, uint AppId, ulong ManifestId, string Branch, uint Version, string InstallDir, byte[] DepotKey);
}
