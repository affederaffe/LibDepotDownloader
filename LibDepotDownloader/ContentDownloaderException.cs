using System;


namespace LibDepotDownloader
{
    public class ContentDownloaderException(string? message) : Exception(message);
}
