using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;

using SteamKit2;


namespace LibDepotDownloader
{
    public static class Utils
    {
        public static string SteamOs => OperatingSystem.IsWindows()? "windows"
            : OperatingSystem.IsMacOS() ? "macos"
                : OperatingSystem.IsLinux() ? "linux"
            : "unknown";

        public static string SteamArch => Environment.Is64BitOperatingSystem ? "64" : "32";

        public static uint AdlerHash(Span<byte> input)
        {
            uint a = 0, b = 0;
            foreach (byte t in input)
            {
                a = (a + t) % 65521;
                b = (b + a) % 65521;
            }

            return a | (b << 16);
        }

        public static List<DepotManifest.ChunkData> ValidateSteam3FileChecksums(FileStream fs, IEnumerable<DepotManifest.ChunkData> chunkData)
        {
            List<DepotManifest.ChunkData> neededChunks = [];

            foreach (DepotManifest.ChunkData data in chunkData)
            {
                int dataLength = (int)data.UncompressedLength;
                byte[] chunk = ArrayPool<byte>.Shared.Rent(dataLength);
                fs.Seek((long)data.Offset, SeekOrigin.Begin);
                int read = fs.Read(chunk, 0, dataLength);
                uint adler = AdlerHash(chunk.AsSpan(read));
                if (adler != data.Checksum)
                    neededChunks.Add(data);
                ArrayPool<byte>.Shared.Return(chunk);
            }

            return neededChunks;
        }
    }
}
