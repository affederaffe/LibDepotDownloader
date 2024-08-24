using System.Collections.Generic;

using SteamKit2;


namespace LibDepotDownloader
{
    internal sealed record DepotFilesData(DepotDownloadInfo DepotDownloadInfo, string StagingDir, DepotDownloadProgress DepotDownloadProgress, DepotManifest Manifest, DepotManifest? PreviousManifest, List<DepotManifest.FileData> FilteredFiles, HashSet<string> AllFileNames);
}
