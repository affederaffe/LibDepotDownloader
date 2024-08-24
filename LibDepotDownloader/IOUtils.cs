using System;
using System.IO;


namespace LibDepotDownloader
{
    internal class IOUtils
    {
        public static bool TryDeleteFile(string path)
        {
            try
            {
                File.Delete(path);
                return true;
            }
            catch (ArgumentException) { }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            return false;
        }
    }
}
