using System.IO;
using System.Threading;


namespace LibDepotDownloader
{
    internal class FileStreamData(FileStream? fileStream, SemaphoreSlim fileLock, int chunksToDownload)
    {
        public FileStream? FileStream = fileStream;
        public readonly SemaphoreSlim FileLock = fileLock;
        public int ChunksToDownload = chunksToDownload;
    }
}
