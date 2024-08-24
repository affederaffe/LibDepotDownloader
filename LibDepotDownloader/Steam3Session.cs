using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using SteamKit2;
using SteamKit2.Authentication;
using SteamKit2.Internal;


namespace LibDepotDownloader
{
    public sealed class Steam3Session : IDisposable
    {
        private readonly SteamUser.LogOnDetails _logOnDetails = new();
        private readonly SteamUser _steamUser;
        private readonly SteamCloud _steamCloud;
        private readonly SteamUnifiedMessages.UnifiedService<IPublishedFile> _steamPublishedFile;

        private readonly Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> _appInfos = [];
        private readonly Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> _packageInfos = [];
        private readonly Dictionary<uint, Dictionary<string, byte[]>> _appBetaPasswords = [];

        private readonly TaskCompletionSource<SteamApps.LicenseListCallback> _licenseListTsc = new();

        private TaskCompletionSource? _connectTcs;
        private TaskCompletionSource<EResult>? _logOnTcs;

        private bool _isConnected;
        private bool _isLoggedOn;

        public Steam3Session()
        {
            SteamConfiguration config = SteamConfiguration.Create(static builder => builder
                .WithHttpClientFactory(HttpClientFactory.CreateIPv4HttpClient));
            SteamClient = new SteamClient(config);
            _steamUser = SteamClient.GetHandler<SteamUser>()!;
            SteamApps = SteamClient.GetHandler<SteamApps>()!;
            SteamContent = SteamClient.GetHandler<SteamContent>()!;
            _steamCloud = SteamClient.GetHandler<SteamCloud>()!;
            SteamUnifiedMessages steamUnifiedMessages = SteamClient.GetHandler<SteamUnifiedMessages>()!;
            _steamPublishedFile = steamUnifiedMessages.CreateService<IPublishedFile>();
            SteamClient.Subscribe<SteamClient.ConnectedCallback>(OnConnected);
            SteamClient.Subscribe<SteamClient.DisconnectedCallback>(OnDisconnected);
            SteamClient.Subscribe<SteamUser.LoggedOnCallback>(OnLoggedOn);
            SteamClient.Subscribe<SteamUser.LoggedOffCallback>(OnLoggedOff);
            SteamClient.Subscribe<SteamApps.LicenseListCallback>(OnLicenseList);
        }

        public async ValueTask ConnectAsync(CancellationToken cancellationToken)
        {
            if (_isConnected)
                return;

            _connectTcs = new TaskCompletionSource();
            await using CancellationTokenRegistration disposable = cancellationToken.Register(() => _connectTcs.TrySetCanceled());
            SteamClient.Connect();
            await _connectTcs.Task;
        }

        public async ValueTask<EResult> LogOnAsync(AuthPollResult authPollResult, CancellationToken cancellationToken)
        {
            if (_isLoggedOn)
                return EResult.OK;

            _logOnTcs = new TaskCompletionSource<EResult>();
            await using CancellationTokenRegistration disposable = cancellationToken.Register(() => _logOnTcs.TrySetCanceled());
            _logOnDetails.Username = authPollResult.AccountName;
            _logOnDetails.AccessToken = authPollResult.RefreshToken;
            _steamUser.LogOn(_logOnDetails);
            return await _logOnTcs.Task;
        }

        private void OnLicenseList(SteamApps.LicenseListCallback licenseList)
        {
            _licenseListTsc.TrySetResult(licenseList);
        }

        public SteamClient SteamClient { get; }

        public SteamApps SteamApps { get; }

        public SteamContent SteamContent { get; }

        public async Task<SteamApps.PICSProductInfoCallback.PICSProductInfo?> GetAppInfoAsync(uint appId)
        {
            if (_appInfos.TryGetValue(appId, out SteamApps.PICSProductInfoCallback.PICSProductInfo? cachedAppInfo))
                return cachedAppInfo;

            SteamApps.PICSTokensCallback methodTokens = await SteamApps.PICSGetAccessTokens(appId, null);
            if (methodTokens.AppTokensDenied.Contains(appId))
                return null;

            SteamApps.PICSRequest request = new(appId) { AccessToken = methodTokens.AppTokens.GetValueOrDefault(appId, 0UL) };
            AsyncJobMultiple<SteamApps.PICSProductInfoCallback>.ResultSet productInfos = await SteamApps.PICSGetProductInfo(request, null);
            if (productInfos.Results is null)
                return null;

            foreach (SteamApps.PICSProductInfoCallback result in productInfos.Results)
            {
                foreach (KeyValuePair<uint,SteamApps.PICSProductInfoCallback.PICSProductInfo> appInfo in result.Apps)
                    _appInfos[appInfo.Key] = appInfo.Value;

                foreach (uint unknownApp in result.UnknownApps)
                    _appInfos.Remove(unknownApp);
            }

            return _appInfos.GetValueOrDefault(appId);
        }

        public async Task<Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo>?> GetPackageInfoAsync(IEnumerable<uint> packageIds)
        {
            List<uint> packages = packageIds.ToList();

            if (packages.All(_packageInfos.ContainsKey))
                return _packageInfos;

            packages.RemoveAll(_packageInfos.ContainsKey);
            IReadOnlyCollection<SteamApps.LicenseListCallback.License> licences = await GetLicenseListAsync();
            IEnumerable<SteamApps.PICSRequest> packageRequests = packages.Select(id => new SteamApps.PICSRequest(id) { AccessToken = licences.FirstOrDefault(licence => licence.PackageID == id)?.AccessToken ?? 0 });
            AsyncJobMultiple<SteamApps.PICSProductInfoCallback>.ResultSet productInfos = await SteamApps.PICSGetProductInfo([], packageRequests);

            foreach (SteamApps.PICSProductInfoCallback packageInfo in productInfos.Results!)
            {
                foreach (KeyValuePair<uint,SteamApps.PICSProductInfoCallback.PICSProductInfo> package in packageInfo.Packages)
                    _packageInfos[package.Key] = package.Value;

                foreach (uint unknownPackage in packageInfo.UnknownPackages)
                    _packageInfos.Remove(unknownPackage);
            }

            return _packageInfos;
        }

        public async Task<bool> TryRequestFreeAppLicenseAsync(uint appId)
        {
            SteamApps.FreeLicenseCallback response = await SteamApps.RequestFreeLicense(appId);
            return response.GrantedApps.Contains(appId);
        }

        public async Task<byte[]?> RequestDepotKeyAsync(uint depotId, uint appId = 0)
        {
            SteamApps.DepotKeyCallback response = await SteamApps.GetDepotDecryptionKey(depotId, appId);
            return response.Result != EResult.OK ? null : response.DepotKey;
        }

        public async Task<ulong> GetDepotManifestRequestCodeAsync(uint depotId, uint appId, ulong manifestId, string branch) => await SteamContent.GetManifestRequestCode(depotId, appId, manifestId, branch);

        public async Task<Dictionary<string, byte[]>?> GetAppBetaKeysAsync(uint appId, string password)
        {
            if (_appBetaPasswords.TryGetValue(appId, out Dictionary<string, byte[]>? appBetaPasswords))
                return appBetaPasswords;

            SteamApps.CheckAppBetaPasswordCallback result = await SteamApps.CheckAppBetaPassword(appId, password);
            _appBetaPasswords[appId] = result.BetaPasswords;
            return result.Result != EResult.OK ? null : result.BetaPasswords;
        }

        public async Task<PublishedFileDetails?> GetPublishedFileDetailsAsync(uint appId, PublishedFileID publishedFileId)
        {
            CPublishedFile_GetDetails_Request publishedFileRequest = new() { appid = appId };
            publishedFileRequest.publishedfileids.Add(publishedFileId);
            SteamUnifiedMessages.ServiceMethodResponse response = await _steamPublishedFile.SendMessage(api => api.GetDetails(publishedFileRequest));
            if (response.Result != EResult.OK)
                return null;
            CPublishedFile_GetDetails_Response getDetailsResponse = response.GetDeserializedResponse<CPublishedFile_GetDetails_Response>();
            return getDetailsResponse.publishedfiledetails.FirstOrDefault();
        }

        public async Task<SteamCloud.UGCDetailsCallback?> GetUgcDetailsAsync(UGCHandle ugcHandle)
        {
            SteamCloud.UGCDetailsCallback response = await _steamCloud.RequestUGCDetails(ugcHandle);
            return response.Result != EResult.OK ? null : response;
        }

        public async ValueTask<ReadOnlyCollection<SteamApps.LicenseListCallback.License>> GetLicenseListAsync()
        {
            SteamApps.LicenseListCallback callback = await _licenseListTsc.Task.ConfigureAwait(false);
            return callback.LicenseList;
        }

        public async Task<bool> GetAccountHasAccessAsync(uint appId, uint depotId)
        {
            if (_steamUser.SteamID is null || appId == SteamConstants.InvalidAppId)
                return false;

            List<uint> licenseQuery;
            if (_steamUser.SteamID.AccountType == EAccountType.AnonUser)
            {
                licenseQuery = new List<uint> { 17906 };
            }
            else
            {
                ReadOnlyCollection<SteamApps.LicenseListCallback.License> licenses = await GetLicenseListAsync();
                if (licenses.Select(static x => x.PackageID) is not { } packageIds)
                    return false;
                licenseQuery = packageIds.ToList();
            }

            Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo>? packageInfos = await GetPackageInfoAsync(licenseQuery);
            if (packageInfos is null)
                return false;

            foreach (uint license in licenseQuery)
            {
                if (!packageInfos.TryGetValue(license, out SteamApps.PICSProductInfoCallback.PICSProductInfo? package))
                    continue;
                if (package.KeyValues["appids"].Children.Any(child => child.AsUnsignedInteger() == depotId))
                    return true;
                if (package.KeyValues["depotids"].Children.Any(child => child.AsUnsignedInteger() == depotId))
                    return true;
            }

            return false;
        }

        private void OnConnected(SteamClient.ConnectedCallback connected)
        {
            _isConnected = true;
            _connectTcs?.TrySetResult();
        }

        private void OnLoggedOn(SteamUser.LoggedOnCallback loggedOn)
        {
            if (loggedOn.Result == EResult.OK)
                _isLoggedOn = true;
            _logOnTcs?.TrySetResult(loggedOn.Result);
        }

        private void OnDisconnected(SteamClient.DisconnectedCallback disconnected)
        {
            _isConnected = false;
        }

        private void OnLoggedOff(SteamUser.LoggedOffCallback obj)
        {
            _isLoggedOn = false;
        }

        /// <inheritdoc />
        public void Dispose()
        {
            SteamClient.Disconnect();
        }
    }
}
