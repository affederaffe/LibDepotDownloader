using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using SteamKit2;
using SteamKit2.CDN;


namespace LibDepotDownloader
{
    /// <summary>
    /// CDNClientPool provides a pool of connections to CDN endpoints, requesting CDN tokens as needed
    /// </summary>
    internal class CdnClientPool : IAsyncDisposable
    {
        private const int ServerEndpointMinimumSize = 8;

        private readonly SteamClient _steamClient;
        private readonly SteamContent _steamContent;
        private readonly uint _appId;

        private readonly ConcurrentStack<Server> _activeConnectionPool;
        private readonly BlockingCollection<Server> _availableServerEndpoints;

        private readonly AutoResetEvent _populatePoolEvent;
        private readonly Task _monitorTask;
        private readonly CancellationTokenSource _shutdownToken;

        public CdnClientPool(SteamClient steamClient, SteamContent steamContent, uint appId)
        {
            _steamClient = steamClient;
            _steamContent = steamContent;
            _appId = appId;
            CdnClient = new Client(steamClient);

            _activeConnectionPool = new ConcurrentStack<Server>();
            _availableServerEndpoints = new BlockingCollection<Server>();

            _populatePoolEvent = new AutoResetEvent(true);
            _shutdownToken = new CancellationTokenSource();

            _monitorTask = Task.Factory.StartNew(ConnectionPoolMonitorAsync).Unwrap();
        }

        public Client CdnClient { get; }

        public Server? ProxyServer { get; private set; }

        public CancellationTokenSource? ExhaustedToken { get; set; }

        private async Task<IReadOnlyCollection<Server>?> FetchBootstrapServerListAsync()
        {
            try
            {
                return await _steamContent.GetServersForSteamPipe();
            }
            catch
            {
                return null;
            }
        }

        private async Task ConnectionPoolMonitorAsync()
        {
            bool didPopulate = false;

            while (!_shutdownToken.IsCancellationRequested)
            {
                _populatePoolEvent.WaitOne(TimeSpan.FromSeconds(1));

                switch (_availableServerEndpoints.Count)
                {
                    // We want the Steam session so we can take the CellID from the session and pass it through to the ContentServer Directory Service
                    case < ServerEndpointMinimumSize when _steamClient.IsConnected:
                    {
                        IReadOnlyCollection<Server>? servers = await FetchBootstrapServerListAsync().ConfigureAwait(false);

                        if (servers is null || servers.Count == 0)
                        {
                            if (ExhaustedToken is not null)
                                await ExhaustedToken.CancelAsync();
                            return;
                        }

                        ProxyServer = servers.FirstOrDefault(static x => x.UseAsProxy);

                        IOrderedEnumerable<Server> weightedCdnServers = servers.Where(server =>
                        {
                            bool isEligibleForApp = server.AllowedAppIds.Length == 0 || server.AllowedAppIds.Contains(_appId);
                            return isEligibleForApp && server.Type is "SteamCache" or "CDN";
                        }).OrderBy(static server => server.WeightedLoad);

                        foreach (Server server in weightedCdnServers)
                        {
                            for (int i = 0; i < server.NumEntries; i++)
                                _availableServerEndpoints.Add(server);
                        }

                        didPopulate = true;
                        break;
                    }
                    case 0 when !_steamClient.IsConnected && didPopulate:
                    {
                        if (ExhaustedToken is not null)
                            await ExhaustedToken.CancelAsync();
                        return;
                    }
                }
            }
        }

        private Server BuildConnection(CancellationToken token)
        {
            if (_availableServerEndpoints.Count < ServerEndpointMinimumSize)
                _populatePoolEvent.Set();
            return _availableServerEndpoints.Take(token);
        }

        public Server GetConnection(CancellationToken token)
        {
            if (!_activeConnectionPool.TryPop(out Server? connection))
                connection = BuildConnection(token);
            return connection;
        }

        public void ReturnConnection(Server? server)
        {
            if (server is null)
                return;
            _activeConnectionPool.Push(server);
        }

        /// <inheritdoc />
        public async ValueTask DisposeAsync()
        {
            await _shutdownToken.CancelAsync();
            await _monitorTask;
        }
    }
}
