using System.Collections.Generic;


namespace LibDepotDownloader
{
    internal sealed record DepotFilesData(DepotDownloadInfo DepotDownloadInfo, string StagingDir, DepotDownloadProgress DepotDownloadProgress, ProtoManifest Manifest, ProtoManifest? PreviousManifest, List<ProtoManifest.FileData> FilteredFiles, HashSet<string> AllFileNames);
}
