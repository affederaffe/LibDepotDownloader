using System;
using System.Collections.Generic;
using System.IO;


namespace LibDepotDownloader
{
    public static class Utils
    {
        public static string SteamOs => OperatingSystem.IsWindows()? "windows"
            : OperatingSystem.IsMacOS() ? "macos"
                : OperatingSystem.IsLinux() ? "linux"
            : "unknown";

        public static string SteamArch => Environment.Is64BitOperatingSystem ? "64" : "32";

        public static byte[] AdlerHash(Span<byte> input)
        {
            uint a = 0, b = 0;
            foreach (byte t in input)
            {
                a = (a + t) % 65521;
                b = (b + a) % 65521;
            }

            return BitConverter.GetBytes(a | (b << 16));
        }

        public static List<ProtoManifest.ChunkData> ValidateSteam3FileChecksums(FileStream fs, IEnumerable<ProtoManifest.ChunkData> chunkData)
        {
            List<ProtoManifest.ChunkData> neededChunks = new();

            foreach (ProtoManifest.ChunkData data in chunkData)
            {
                byte[] chunk = new byte[data.UncompressedLength];
                fs.Seek((long)data.Offset, SeekOrigin.Begin);
                int read = fs.Read(chunk, 0, (int)data.UncompressedLength);

                byte[] tempChunk;
                if (read < data.UncompressedLength)
                {
                    tempChunk = new byte[read];
                    Array.Copy(chunk, 0, tempChunk, 0, read);
                }
                else
                {
                    tempChunk = chunk;
                }

                Span<byte> adler = AdlerHash(tempChunk);
                if (!adler.SequenceEqual(data.Checksum))
                    neededChunks.Add(data);
            }

            return neededChunks;
        }
    }
}
