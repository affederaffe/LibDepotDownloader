namespace LibDepotDownloader
{
    public record ChunkMatch(ProtoManifest.ChunkData OldChunk, ProtoManifest.ChunkData NewChunk);
}
