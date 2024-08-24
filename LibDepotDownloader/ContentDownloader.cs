using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using SteamKit2;
using SteamKit2.CDN;
using SteamKit2.Internal;


namespace LibDepotDownloader
{
    public class ContentDownloader(DownloadConfig downloadConfig, Steam3Session steam3Session)
    {
        private async Task<KeyValue?> GetSteam3AppSectionAsync(uint appId, EAppInfoSection section)
        {
            SteamApps.PICSProductInfoCallback.PICSProductInfo? appInfo = await steam3Session.GetAppInfoAsync(appId);
            if (appInfo is null)
                return null;

            string sectionKey = section switch
            {
                EAppInfoSection.Common => "common",
                EAppInfoSection.Extended => "extended",
                EAppInfoSection.Config => "config",
                EAppInfoSection.Depots => "depots",
                _ => throw new ArgumentOutOfRangeException(nameof(section))
            };

            return appInfo.KeyValues.Children.FirstOrDefault(x => x.Name ==  sectionKey);
        }

        public async Task<ulong> GetSteam3DepotManifestAsync(uint depotId, uint appId, string branch, string? betaPassword = null)
        {
            KeyValue? depots = await GetSteam3AppSectionAsync(appId, EAppInfoSection.Depots);

            if (depots is null)
                throw new InvalidOperationException($"Failed to retrieve depots for app {appId}.");

            KeyValue depotChild = depots[depotId.ToString(NumberFormatInfo.InvariantInfo)];

            if (depotChild == KeyValue.Invalid)
                throw new InvalidOperationException($"App {appId} doesn't contain a depot {depotId}.");

            // Shared depots can either provide manifests, or leave you relying on their parent app.
            // It seems that with the latter, "sharedinstall" will exist (and equals 2 in the one existance I know of).
            // Rather than relay on the unknown sharedinstall key, just look for manifests. Test cases: 111710, 346680.
            if (depotChild["manifests"] == KeyValue.Invalid && depotChild["depotfromapp"] != KeyValue.Invalid)
            {
                uint otherAppId = depotChild["depotfromapp"].AsUnsignedInteger();
                // This shouldn't ever happen, but ya never know with Valve. Don't infinite loop.
                if (otherAppId == appId)
                    throw new InvalidOperationException($"App {appId}, Depot {depotId} has depotfromapp of {otherAppId}!");

                appId = otherAppId;
                betaPassword = null;
                depots = await GetSteam3AppSectionAsync(appId, EAppInfoSection.Depots);

                if (depots is null)
                    throw new InvalidOperationException($"Failed to retrieve depots for app {appId}.");

                if (depotChild == KeyValue.Invalid)
                    throw new InvalidOperationException($"App {appId} doesn't contain a depot {depotId}.");
            }

            KeyValue manifests = depotChild["manifests"];
            KeyValue manifestsEncrypted = depotChild["encryptedmanifests"];

            if (manifests.Children.Count == 0 && manifestsEncrypted.Children.Count == 0)
                throw new InvalidOperationException($"No Manifests for appId {appId}.");

            KeyValue node = manifests[branch]["gid"];

            if (node == KeyValue.Invalid && !string.Equals(branch, SteamConstants.DefaultBranch, StringComparison.OrdinalIgnoreCase))
            {
                KeyValue nodeEncrypted = manifestsEncrypted[branch];

                if (nodeEncrypted == KeyValue.Invalid)
                    throw new InvalidOperationException($"No encrypted Manifests for appId {appId} on branch {branch}.");

                KeyValue encryptedGid = nodeEncrypted["gid"];

                if (encryptedGid == KeyValue.Invalid || betaPassword is null)
                    throw new InvalidOperationException($"Unhandled depot encryption for depotId {depotId}");

                Dictionary<string, byte[]>? betaKeys = await steam3Session.GetAppBetaKeysAsync(appId, betaPassword);

                if (betaKeys is null || !betaKeys.TryGetValue(branch, out byte[]? key))
                    throw new UnauthorizedAccessException($"Failed to retrieve beta keys for {appId} on branch {branch} with password {betaPassword}.");

                byte[] input = Convert.FromHexString(encryptedGid.Value!);
                byte[] manifestBytes = CryptoHelper.SymmetricDecrypt(input, key);
                return BitConverter.ToUInt64(manifestBytes, 0);
            }

            if (node.Value is null)
                throw new InvalidOperationException($"No gid on branch {branch}.");

            return ulong.Parse(node.Value, NumberFormatInfo.InvariantInfo);
        }

        public async Task<string?> GetAppNameAsync(uint appId)
        {
            KeyValue? info = await GetSteam3AppSectionAsync(appId, EAppInfoSection.Common);
            return info?["name"].AsString();
        }

        public async Task<string?> DownloadPublishedFileAsync(uint appId, ulong publishedFileId, CancellationToken cancellationToken, IProgress<double>? progress = null)
        {
            PublishedFileDetails? details = await steam3Session.GetPublishedFileDetailsAsync(appId, publishedFileId);

            if (!string.IsNullOrEmpty(details?.file_url))
                return await DownloadWebFile(appId, details.filename, details.file_url);

            if (details?.hcontent_file > 0)
            {
                string[]? paths = await DownloadAppAsync(appId, new List<(uint, ulong)> { (appId, details.hcontent_file) }, SteamConstants.DefaultBranch, null, null, null, false, true, cancellationToken, progress);
                if (paths?.Length == 1)
                    return paths[0];
            }

            return null;
        }

        private async Task<string?> DownloadWebFile(uint appId, string fileName, string url)
        {
            if (!TryCreateDirectories(appId, 0, out string? installDir))
                return null;

            string stagingDir = Path.Combine(installDir, SteamConstants.StagingDir);
            string fileStagingPath = Path.Combine(stagingDir, fileName);
            string fileFinalPath = Path.Combine(installDir, fileName);

            Directory.CreateDirectory(Path.GetDirectoryName(fileFinalPath)!);
            Directory.CreateDirectory(Path.GetDirectoryName(fileStagingPath)!);

            await using FileStream file = File.OpenWrite(fileStagingPath);
            using HttpClient client = HttpClientFactory.CreateIPv4HttpClient();
            Stream responseStream = await client.GetStreamAsync(url);
            await responseStream.CopyToAsync(file);

            IOUtils.TryDeleteFile(fileFinalPath);
            File.Move(fileStagingPath, fileFinalPath);
            return fileFinalPath;
        }

        public async Task<string[]?> DownloadAppAsync(uint appId, List<(uint DepotId, ulong ManifestId)> depotManifestIds, string branch, string? os, string? arch, string? language, bool lv, bool isUgc, CancellationToken cancellationToken, IProgress<double>? progress = null)
        {
            if (!await steam3Session.GetAccountHasAccessAsync(appId, appId) || !await steam3Session.TryRequestFreeAppLicenseAsync(appId))
            {
                string? contentName = await GetAppNameAsync(appId);
                throw new InvalidOperationException($"App {appId} ({contentName}) is not available from this account.");
            }

            bool hasSpecificDepots = depotManifestIds.Count > 0;
            List<uint> depotIdsFound = [];
            List<uint> depotIdsExpected = depotManifestIds.Select(static x => x.DepotId).ToList();
            KeyValue depots = await GetSteam3AppSectionAsync(appId, EAppInfoSection.Depots) ?? throw new InvalidOperationException($"Failed to fetch depots for app {appId}.");

            if (isUgc)
            {
                uint workshopDepot = depots["workshopdepot"].AsUnsignedInteger();
                if (workshopDepot != 0 && !depotIdsExpected.Contains(workshopDepot))
                {
                    depotIdsExpected.Add(workshopDepot);
                    depotManifestIds = depotManifestIds.Select(pair => (workshopDepot, pair.ManifestId)).ToList();
                }

                depotIdsFound.AddRange(depotIdsExpected);
            }
            else
            {
                foreach (KeyValue depotSection in depots.Children)
                {
                    if (depotSection.Children.Count == 0)
                        continue;

                    if (!uint.TryParse(depotSection.Name, out uint id) || (hasSpecificDepots && !depotIdsExpected.Contains(id)))
                        continue;

                    if (!hasSpecificDepots)
                    {
                        KeyValue depotConfig = depotSection["config"];
                        if (depotConfig != KeyValue.Invalid)
                        {
                            if (!downloadConfig.DownloadAllPlatforms && depotConfig["oslist"] != KeyValue.Invalid && !string.IsNullOrWhiteSpace(depotConfig["oslist"].Value))
                            {
                                string[] osList = depotConfig["oslist"].Value!.Split(',');
                                if (!osList.Contains(os ?? Utils.SteamOs))
                                    continue;
                            }

                            if (depotConfig["osarch"] != KeyValue.Invalid && !string.IsNullOrWhiteSpace(depotConfig["osarch"].Value))
                            {
                                string? depotArch = depotConfig["osarch"].Value;
                                if (depotArch != (arch ?? Utils.SteamArch))
                                    continue;
                            }

                            if (!downloadConfig.DownloadAllLanguages && depotConfig["language"] != KeyValue.Invalid && !string.IsNullOrWhiteSpace(depotConfig["language"].Value))
                            {
                                string? depotLang = depotConfig["language"].Value;
                                if (depotLang != (language ?? "english"))
                                    continue;
                            }

                            if (!lv && depotConfig["lowviolence"] != KeyValue.Invalid && depotConfig["lowviolence"].AsBoolean())
                                continue;
                        }
                    }

                    depotIdsFound.Add(id);

                    if (!hasSpecificDepots)
                        depotManifestIds.Add((id, SteamConstants.InvalidManifestId));
                }

                if (depotManifestIds.Count == 0 && !hasSpecificDepots)
                    throw new ContentDownloaderException($"Couldn't find any depots to download for app {appId}");

                if (depotIdsFound.Count < depotIdsExpected.Count)
                {
                    IEnumerable<uint> remainingDepotIds = depotIdsExpected.Except(depotIdsFound);
                    throw new ContentDownloaderException($"Depot {string.Join(", ", remainingDepotIds)} not listed for app {appId}");
                }
            }

            List<DepotDownloadInfo> infos = [];
            foreach ((uint DepotId, ulong ManifestId) depotManifest in depotManifestIds)
            {
                DepotDownloadInfo? info = await GetDepotInfoAsync(depotManifest.DepotId, appId, depotManifest.ManifestId, branch);
                if (info is not null)
                    infos.Add(info);
            }

            return await DownloadSteam3Async(appId, infos, cancellationToken, progress).ConfigureAwait(false);
        }

        private async Task<string[]?> DownloadSteam3Async(uint appId, List<DepotDownloadInfo> depots, CancellationToken cancellationToken, IProgress<double>? progress = null)
        {
            GlobalDownloadProgress globalDownloadProgress = new();
            List<DepotFilesData> depotsToDownload = new(depots.Count);
            HashSet<string> allFileNamesAllDepots = [];

            await using CdnClientPool cdnClientPool = new(steam3Session.SteamClient, steam3Session.SteamContent, appId);

            // First, fetch all the manifests for each depot (including previous manifests) and perform the initial setup
            foreach (DepotDownloadInfo depot in depots)
            {
                DepotFilesData? depotFileData = await ProcessDepotManifestAndFilesAsync(cdnClientPool, depot, cancellationToken, progress);
                if (depotFileData is not null)
                {
                    depotsToDownload.Add(depotFileData);
                    allFileNamesAllDepots.UnionWith(depotFileData.AllFileNames);
                }
            }

            // If we're about to write all the files to the same directory, we will need to first de-duplicate any files by path
            // This is in last-depot-wins order, from Steam or the list of depots supplied by the user
            if (!string.IsNullOrWhiteSpace(downloadConfig.InstallDirectory) && depotsToDownload.Count > 0)
            {
                HashSet<string> claimedFileNames = [];
                for (int i = depotsToDownload.Count - 1; i >= 0; i--)
                {
                    // For each depot, remove all files from the list that have been claimed by a later depot
                    depotsToDownload[i].FilteredFiles.RemoveAll(file => claimedFileNames.Contains(file.FileName));
                    claimedFileNames.UnionWith(depotsToDownload[i].AllFileNames);
                }
            }

            foreach (DepotFilesData depotFileData in depotsToDownload)
                await DownloadSteam3DepotFilesAsync(cdnClientPool, depotFileData, allFileNamesAllDepots, globalDownloadProgress, cancellationToken);

            return depots.Select(static x => x.InstallDir).ToArray();
        }

        private async Task<DepotFilesData?> ProcessDepotManifestAndFilesAsync(CdnClientPool cdnClientPool, DepotDownloadInfo depot, CancellationToken cancellationToken, IProgress<double>? progress = null)
        {
            DepotDownloadProgress depotDownloadProgress = new(progress);
            DepotManifest? oldDepotManifest = null;
            DepotManifest? newManifest = null;
            ulong manifestRequestCode = 0;
            DateTime manifestRequestCodeExpiration = DateTime.MinValue;

            do
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    Server connection = cdnClientPool.GetConnection(cancellationToken);
                    DateTime now = DateTime.Now;

                    // In order to download this manifest, we need the current manifest request code
                    // The manifest request code is only valid for a specific period in time
                    if (manifestRequestCode == 0 || now >= manifestRequestCodeExpiration)
                    {
                        manifestRequestCode = await steam3Session.GetDepotManifestRequestCodeAsync(depot.Id, depot.AppId, depot.ManifestId, depot.Branch);
                        // This code will hopefully be valid for one period following the issuing period
                        manifestRequestCodeExpiration = now.Add(TimeSpan.FromMinutes(5));

                        // If we could not get the manifest code, this is a fatal error
                        if (manifestRequestCode == 0)
                            return null;
                    }

                    newManifest = await cdnClientPool.CdnClient.DownloadManifestAsync(depot.Id, depot.ManifestId, manifestRequestCode, connection, depot.DepotKey, cdnClientPool.ProxyServer).ConfigureAwait(false);
                    cdnClientPool.ReturnConnection(connection);
                }
                catch (TaskCanceledException) { }
                catch (SteamKitWebRequestException e)
                {
                    if (e.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden or HttpStatusCode.NotFound)
                        return null;
                }
                catch (OperationCanceledException)
                {
                    return null;
                }
            } while (newManifest is null);

            // Throw the cancellation exception if requested so that this task is marked failed
            cancellationToken.ThrowIfCancellationRequested();

            newManifest.Files!.Sort(static (x, y) => string.Compare(x.FileName, y.FileName, StringComparison.Ordinal));

            string stagingDir = Path.Combine(depot.InstallDir, SteamConstants.StagingDir);

            List<DepotManifest.FileData> filesAfterExclusions = newManifest.Files.AsParallel().Where(f => TestIsFileIncluded(f.FileName)).ToList();
            HashSet<string> allFileNames = new(filesAfterExclusions.Count);

            // Pre-process
            foreach (DepotManifest.FileData file in filesAfterExclusions)
            {
                allFileNames.Add(file.FileName);

                string fileFinalPath = Path.Combine(depot.InstallDir, file.FileName);
                string fileStagingPath = Path.Combine(stagingDir, file.FileName);

                if (file.Flags.HasFlag(EDepotFileFlag.Directory))
                {
                    Directory.CreateDirectory(fileFinalPath);
                    Directory.CreateDirectory(fileStagingPath);
                }
                else
                {
                    // Some manifests don't explicitly include all necessary directories
                    Directory.CreateDirectory(Path.GetDirectoryName(fileFinalPath)!);
                    Directory.CreateDirectory(Path.GetDirectoryName(fileStagingPath)!);

                    depotDownloadProgress.CompleteDownloadSize += file.TotalSize;
                }
            }

            return new DepotFilesData(depot, stagingDir, depotDownloadProgress, newManifest, oldDepotManifest, filesAfterExclusions, allFileNames);
        }

        private async Task DownloadSteam3DepotFilesAsync(CdnClientPool cdnClientPool, DepotFilesData depotFilesData, HashSet<string> allFileNamesAllDepots, GlobalDownloadProgress downloadProgress, CancellationToken cancellationToken)
        {
            DepotManifest.FileData[] files = depotFilesData.FilteredFiles.Where(static f => !f.Flags.HasFlag(EDepotFileFlag.Directory)).ToArray();
            ConcurrentQueue<(FileStreamData FileStreamData, DepotManifest.FileData FileData, DepotManifest.ChunkData Chunk)> networkChunkQueue = new();

            foreach (DepotManifest.FileData fileData in files)
                await DownloadSteam3AsyncDepotFileAsync(depotFilesData, fileData, networkChunkQueue, cancellationToken);

            foreach ((FileStreamData FileStreamData, DepotManifest.FileData FileData, DepotManifest.ChunkData Chunk) q in networkChunkQueue)
                await DownloadSteam3DepotFileChunkAsync(cdnClientPool, downloadProgress, depotFilesData, q.FileData, q.FileStreamData, q.Chunk, cancellationToken);

            // Check for deleted files if updating the depot.
            if (depotFilesData.PreviousManifest is not null)
            {
                HashSet<string> previousFilteredFiles = depotFilesData.PreviousManifest.Files!
                    .AsParallel()
                    .Where(f => TestIsFileIncluded(f.FileName))
                    .Select(static f => f.FileName)
                    .ToHashSet();

                // Check if we are writing to a single output directory. If not, each depot folder is managed independently
                // Of the list of files in the previous manifest, remove any file names that exist in the current set of all file names
                previousFilteredFiles.ExceptWith(string.IsNullOrWhiteSpace(downloadConfig.InstallDirectory)
                    ? depotFilesData.AllFileNames
                    // Of the list of files in the previous manifest, remove any file names that exist in the current set of all file names across all depots being downloaded
                    : allFileNamesAllDepots);

                foreach (string existingFileName in previousFilteredFiles)
                {
                    string fileFinalPath = Path.Combine(depotFilesData.DepotDownloadInfo.InstallDir, existingFileName);
                    IOUtils.TryDeleteFile(fileFinalPath);
                }
            }
        }

        private async Task DownloadSteam3AsyncDepotFileAsync(DepotFilesData depotFilesData, DepotManifest.FileData file, ConcurrentQueue<(FileStreamData, DepotManifest.FileData, DepotManifest.ChunkData)> networkChunkQueue, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            DepotDownloadInfo depot = depotFilesData.DepotDownloadInfo;
            DepotManifest? oldDepotManifest = depotFilesData.PreviousManifest;
            DepotManifest.FileData? oldManifestFile = null;
            if (oldDepotManifest is not null)
                oldManifestFile = oldDepotManifest.Files?.SingleOrDefault(f => f.FileName == file.FileName);

            string fileFinalPath = Path.Combine(depot.InstallDir, file.FileName);
            string fileStagingPath = Path.Combine(depotFilesData.StagingDir, file.FileName);

            // This may still exist if the previous run exited before cleanup
            IOUtils.TryDeleteFile(fileStagingPath);

            List<DepotManifest.ChunkData> neededChunks;
            FileInfo fi = new(fileFinalPath);
            bool fileDidExist = fi.Exists;
            if (!fileDidExist)
            {
                // create new file. need all chunks
                await using FileStream fs = File.Create(fileFinalPath);
                try
                {
                    fs.SetLength((long)file.TotalSize);
                }
                catch (IOException ex)
                {
                    throw new ContentDownloaderException($"Failed to allocate file {fileFinalPath}: {ex.Message}");
                }

                neededChunks = [..file.Chunks];
            }
            else
            {
                // open existing
                if (oldManifestFile is not null)
                {
                    neededChunks = [];

                    bool hashMatches = oldManifestFile.FileHash.SequenceEqual(file.FileHash);
                    if (downloadConfig.VerifyAll || !hashMatches)
                    {
                        // we have a version of this file, but it doesn't fully match what we want
                        List<ChunkMatch> matchingChunks = [];

                        foreach (DepotManifest.ChunkData chunk in file.Chunks)
                        {
                            DepotManifest.ChunkData? oldChunk = oldManifestFile.Chunks.FirstOrDefault(c => c.ChunkID!.SequenceEqual(chunk.ChunkID!));
                            if (oldChunk != null)
                                matchingChunks.Add(new ChunkMatch(oldChunk, chunk));
                            else
                                neededChunks.Add(chunk);
                        }

                        IOrderedEnumerable<ChunkMatch> orderedChunks = matchingChunks.OrderBy(static x => x.OldChunk.Offset);

                        List<ChunkMatch> copyChunks = [];

                        await using (FileStream fsOld = File.Open(fileFinalPath, FileMode.Open))
                        {
                            foreach (ChunkMatch match in orderedChunks)
                            {
                                fsOld.Seek((long)match.OldChunk.Offset, SeekOrigin.Begin);

                                int chunkLength = (int)match.OldChunk.UncompressedLength;
                                byte[] chunk = ArrayPool<byte>.Shared.Rent(chunkLength);
                                int read = await fsOld.ReadAsync(chunk, cancellationToken);

                                uint adler = Utils.AdlerHash(chunk.AsSpan(read));
                                if (adler != match.OldChunk.Checksum)
                                    neededChunks.Add(match.NewChunk);
                                else
                                    copyChunks.Add(match);
                                ArrayPool<byte>.Shared.Return(chunk);
                            }
                        }

                        if (!hashMatches || neededChunks.Count > 0)
                        {
                            File.Move(fileFinalPath, fileStagingPath);

                            await using FileStream fsOld = File.Open(fileStagingPath, FileMode.Open);
                            await using FileStream fs = File.Open(fileFinalPath, FileMode.Create);
                            try
                            {
                                fs.SetLength((long)file.TotalSize);
                            }
                            catch (IOException ex)
                            {
                                throw new ContentDownloaderException($"Failed to resize file to expected size {fileFinalPath}: {ex.Message}");
                            }

                            foreach (ChunkMatch match in copyChunks)
                            {
                                fsOld.Seek((long)match.OldChunk.Offset, SeekOrigin.Begin);

                                int chunkLength = (int)match.OldChunk.UncompressedLength;
                                byte[] chunk = ArrayPool<byte>.Shared.Rent(chunkLength);
                                int read = await fsOld.ReadAsync(chunk, cancellationToken);

                                fs.Seek((long)match.NewChunk.Offset, SeekOrigin.Begin);
                                await fs.WriteAsync(chunk.AsMemory(read), cancellationToken);
                                ArrayPool<byte>.Shared.Return(chunk);
                            }

                            File.Delete(fileStagingPath);
                        }
                    }
                }
                else
                {
                    // No old manifest or file not in old manifest. We must validate.
                    await using FileStream fs = File.Open(fileFinalPath, FileMode.Open);
                    if ((ulong)fi.Length != file.TotalSize)
                    {
                        try
                        {
                            fs.SetLength((long)file.TotalSize);
                        }
                        catch (IOException ex)
                        {
                            throw new ContentDownloaderException($"Failed to allocate file {fileFinalPath}: {ex.Message}");
                        }
                    }

                    neededChunks = Utils.ValidateSteam3FileChecksums(fs, file.Chunks.OrderBy(static x => x.Offset));
                }

                if (neededChunks.Count == 0)
                {
                    lock (depotFilesData.DepotDownloadProgress)
                        depotFilesData.DepotDownloadProgress.SizeDownloaded += file.TotalSize;

                    return;
                }

                ulong sizeOnDisk = file.TotalSize - (ulong)neededChunks.Select(static x => (long)x.UncompressedLength).Sum();
                lock (depotFilesData.DepotDownloadProgress)
                    depotFilesData.DepotDownloadProgress.SizeDownloaded += sizeOnDisk;
            }

            if (!OperatingSystem.IsWindows())
            {
                bool fileIsExecutable = file.Flags.HasFlag(EDepotFileFlag.Executable);
                if (fileIsExecutable && (!fileDidExist || oldManifestFile is null || !oldManifestFile.Flags.HasFlag(EDepotFileFlag.Executable)))
                    File.SetUnixFileMode(fileFinalPath, File.GetUnixFileMode(fileFinalPath) | UnixFileMode.UserExecute);
                else if (!fileIsExecutable && oldManifestFile is not null && oldManifestFile.Flags.HasFlag(EDepotFileFlag.Executable))
                    File.SetUnixFileMode(fileFinalPath, File.GetUnixFileMode(fileFinalPath) & ~UnixFileMode.UserExecute);
            }

            FileStreamData fileStreamData = new(null, new SemaphoreSlim(1), neededChunks.Count);

            foreach (DepotManifest.ChunkData chunk in neededChunks)
                networkChunkQueue.Enqueue((fileStreamData, file, chunk));
        }

        private static async Task DownloadSteam3DepotFileChunkAsync(
            CdnClientPool cdnClientPool,
            GlobalDownloadProgress downloadProgress,
            DepotFilesData depotFilesData,
            DepotManifest.FileData file,
            FileStreamData fileStreamData,
            DepotManifest.ChunkData chunk,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            DepotDownloadInfo depot = depotFilesData.DepotDownloadInfo;
            DepotDownloadProgress depotDownloadProgress = depotFilesData.DepotDownloadProgress;

            DepotManifest.ChunkData data = new()
            {
                ChunkID = chunk.ChunkID,
                Checksum = chunk.Checksum,
                Offset = chunk.Offset,
                CompressedLength = chunk.CompressedLength,
                UncompressedLength = chunk.UncompressedLength
            };

            DepotChunk? chunkData = null;

            do
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    Server connection = cdnClientPool.GetConnection(cancellationToken);
                    chunkData = await cdnClientPool.CdnClient.DownloadDepotChunkAsync(depot.Id, data,connection, depot.DepotKey, cdnClientPool.ProxyServer).ConfigureAwait(false);
                    cdnClientPool.ReturnConnection(connection);
                }
                catch (TaskCanceledException) { }
                catch (SteamKitWebRequestException e)
                {
                    if (e.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                        break;
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            } while (chunkData is null);

            if (chunkData is null)
                return;

            try
            {
                await fileStreamData.FileLock.WaitAsync(cancellationToken).ConfigureAwait(false);

                if (fileStreamData.FileStream is null)
                {
                    string fileFinalPath = Path.Combine(depot.InstallDir, file.FileName);
                    fileStreamData.FileStream = File.Open(fileFinalPath, FileMode.Open);
                }

                fileStreamData.FileStream.Seek((long)chunkData.ChunkInfo.Offset, SeekOrigin.Begin);
                await fileStreamData.FileStream.WriteAsync(chunkData.Data, cancellationToken);
            }
            finally
            {
                fileStreamData.FileLock.Release();
            }

            int remainingChunks = Interlocked.Decrement(ref fileStreamData.ChunksToDownload);
            if (remainingChunks == 0 && fileStreamData.FileStream is not null)
            {
                await fileStreamData.FileStream.DisposeAsync();
                fileStreamData.FileLock.Dispose();
            }

            ulong sizeDownloaded;
            lock (depotDownloadProgress)
            {
                sizeDownloaded = depotDownloadProgress.SizeDownloaded + (ulong)chunkData.Data.Length;
                depotDownloadProgress.SizeDownloaded = sizeDownloaded;
                depotDownloadProgress.DepotBytesCompressed += chunk.CompressedLength;
                depotDownloadProgress.DepotBytesUncompressed += chunk.UncompressedLength;
            }

            lock (downloadProgress)
            {
                downloadProgress.TotalBytesCompressed += chunk.CompressedLength;
                downloadProgress.TotalBytesUncompressed += chunk.UncompressedLength;
            }

            if (remainingChunks == 0)
                depotDownloadProgress.Report(sizeDownloaded / (double)depotDownloadProgress.CompleteDownloadSize);
        }

        private async Task<DepotDownloadInfo?> GetDepotInfoAsync(uint depotId, uint appId, ulong manifestId, string branch)
        {
            if (appId == SteamConstants.InvalidAppId)
                return null;

            if (!await steam3Session.GetAccountHasAccessAsync(appId, depotId))
                return null;

            if (manifestId == SteamConstants.InvalidManifestId)
            {
                manifestId = await GetSteam3DepotManifestAsync(depotId, appId, branch, downloadConfig.BetaPassword);
                if (manifestId == SteamConstants.InvalidManifestId && !string.Equals(branch, SteamConstants.DefaultBranch, StringComparison.OrdinalIgnoreCase))
                {
                    branch = SteamConstants.DefaultBranch;
                    manifestId = await GetSteam3DepotManifestAsync(depotId, appId, branch);
                }

                if (manifestId == SteamConstants.InvalidManifestId)
                    return null;
            }

            byte[]? depotKey = await steam3Session.RequestDepotKeyAsync(depotId, appId);
            if ( depotKey is null)
                return null;

            uint uVersion = await GetSteam3AppBuildNumber(appId, branch);

            return !TryCreateDirectories(depotId, uVersion, out string? installDir) ? null : new DepotDownloadInfo(depotId, appId, manifestId, branch, uVersion,  installDir, depotKey);
        }

        private async Task<uint> GetSteam3AppBuildNumber(uint appId, string branch)
        {
            if (appId == SteamConstants.InvalidAppId)
                return 0;
            KeyValue? depots = await GetSteam3AppSectionAsync(appId, EAppInfoSection.Depots);
            if (depots is null)
                return 0;
            KeyValue branches = depots["branches"];
            KeyValue node = branches[branch];
            if (node == KeyValue.Invalid)
                return 0;
            KeyValue buildId = node["buildid"];
            if (buildId == KeyValue.Invalid || buildId.Value is null)
                return 0;
            return uint.Parse(buildId.Value, NumberFormatInfo.InvariantInfo);
        }

        private bool TestIsFileIncluded(string filename)
        {
            if (!downloadConfig.UsingFileList)
                return true;

            filename = filename.Replace('\\', '/');

            return downloadConfig.FilesToDownload!.Contains(filename) || downloadConfig.FilesToDownloadRegex!.Select(rgx => rgx.Match(filename)).Any(static m => m.Success);
        }

        private bool TryCreateDirectories(uint depotId, uint depotVersion, [NotNullWhen(true)] out string? installDir)
        {
            installDir = null;
            try
            {
                if (string.IsNullOrWhiteSpace(downloadConfig.InstallDirectory))
                {
                    Directory.CreateDirectory(SteamConstants.DefaultDownloadDir);

                    string depotPath = Path.Combine(SteamConstants.DefaultDownloadDir, depotId.ToString(NumberFormatInfo.InvariantInfo));
                    Directory.CreateDirectory(depotPath);

                    installDir = Path.Combine(depotPath, depotVersion.ToString(NumberFormatInfo.InvariantInfo));
                    Directory.CreateDirectory(installDir);

                    Directory.CreateDirectory(Path.Combine(installDir, SteamConstants.ConfigDir));
                    Directory.CreateDirectory(Path.Combine(installDir, SteamConstants.StagingDir));
                }
                else
                {
                    Directory.CreateDirectory(downloadConfig.InstallDirectory);

                    installDir = downloadConfig.InstallDirectory;

                    Directory.CreateDirectory(Path.Combine(installDir, SteamConstants.ConfigDir));
                    Directory.CreateDirectory(Path.Combine(installDir, SteamConstants.StagingDir));
                }
            }
            catch
            {
                return false;
            }

            return true;
        }
    }
}
