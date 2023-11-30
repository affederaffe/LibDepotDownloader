using System;


namespace LibDepotDownloader
{
    internal class DepotDownloadProgress(IProgress<double>? progress) : IProgress<double>
    {
        public ulong CompleteDownloadSize { get; set; }

        public ulong SizeDownloaded { get; set; }

        public ulong DepotBytesCompressed { get; set; }

        public ulong DepotBytesUncompressed { get; set; }

        /// <inheritdoc />
        public void Report(double value) => progress?.Report(value);
    }
}
