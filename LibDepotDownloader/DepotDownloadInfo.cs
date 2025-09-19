namespace LibDepotDownloader;

public record DepotDownloadInfo(uint DepotId, uint AppId, ulong ManifestId, string Branch, string InstallDir, byte[] DepotKey);