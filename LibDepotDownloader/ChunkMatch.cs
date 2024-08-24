using SteamKit2;


namespace LibDepotDownloader
{
    public record ChunkMatch(DepotManifest.ChunkData OldChunk, DepotManifest.ChunkData NewChunk);
}
