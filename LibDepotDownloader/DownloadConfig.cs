using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

namespace LibDepotDownloader
{
    public class DownloadConfig
    {
        public bool DownloadAllPlatforms { get; set; }

        public bool DownloadAllLanguages { get; set; }

        public string? InstallDirectory { get; set; }

        public bool UsingFileList { get; set; }

        [MemberNotNullWhen(true, nameof(UsingFileList))]
        public HashSet<string>? FilesToDownload { get; set; }

        [MemberNotNullWhen(true, nameof(UsingFileList))]
        public List<Regex>? FilesToDownloadRegex { get; set; }

        public string? BetaPassword { get; set; }

        public bool VerifyAll { get; set; }

        public int MaxDownloads { get; set; } = 1;

        public bool RememberPassword { get; set; }

        public bool UseQrCode { get; set; }
    }
}
