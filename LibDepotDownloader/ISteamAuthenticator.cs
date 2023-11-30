using System.Threading.Tasks;

using SteamKit2.Authentication;


namespace LibDepotDownloader
{
    public interface ISteamAuthenticator : IAuthenticator
    {
        ValueTask DisplayQrCode(string challengeUrl);

        ValueTask<(string? Username, string? Password, bool RememberLogin)> ProvideLoginDetailsAsync();
    }
}
