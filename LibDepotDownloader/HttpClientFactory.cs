using System.Net;
using System.Net.Http;
using System.Net.Sockets;


namespace LibDepotDownloader
{
    public static class HttpClientFactory
    {
        public static HttpClient CreateIPv4HttpClient() =>
            new(
                new SocketsHttpHandler
                {
                    ConnectCallback = static async (context, cancellationToken) =>
                    {
                        IPHostEntry entry = await Dns.GetHostEntryAsync(context.DnsEndPoint.Host, AddressFamily.InterNetwork, cancellationToken);
                        Socket socket = new(SocketType.Stream, ProtocolType.Tcp);
                        socket.NoDelay = true;
                        try
                        {
                            await socket.ConnectAsync(entry.AddressList, context.DnsEndPoint.Port, cancellationToken);
                            return new NetworkStream(socket, true);
                        }
                        catch
                        {
                            socket.Dispose();
                            throw;
                        }
                    }
                }
            );
    }
}
