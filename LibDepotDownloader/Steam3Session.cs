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
    public class Steam3Session
    {
        private readonly DownloadConfig _downloadConfig;
        private readonly SteamUser.LogOnDetails _logOnDetails;
        private readonly ISteamAuthenticator _steamAuthenticator;
        private readonly SteamClient _steamClient;
        private readonly CallbackManager _callbackManager;
        private readonly SteamUser _steamUser;
        private readonly SteamApps _steamApps;
        private readonly SteamContent _steamContent;
        private readonly SteamCloud _steamCloud;
        private readonly SteamUnifiedMessages _steamUnifiedMessages;
        private readonly SteamUnifiedMessages.UnifiedService<IPublishedFile> _steamPublishedFile;

        private bool _reconnect;
        private bool _isConnected;
        private bool _isLoggedOn;
        private ReadOnlyCollection<SteamApps.LicenseListCallback.License>? _licenseList;
        private AuthSession? _authSession;
        private string? _previousGuardData;

        public Steam3Session(DownloadConfig downloadConfig, SteamUser.LogOnDetails details, ISteamAuthenticator steamAuthenticator)
        {
            _downloadConfig = downloadConfig;
            _logOnDetails = details;
            _steamAuthenticator = steamAuthenticator;
            SteamConfiguration config = SteamConfiguration.Create(static builder => builder.WithHttpClientFactory(HttpClientFactory.CreateIPv4HttpClient));
            _steamClient = new SteamClient(config);
            _callbackManager = new CallbackManager(_steamClient);
            _steamUser = _steamClient.GetHandler<SteamUser>()!;
            _steamApps = _steamClient.GetHandler<SteamApps>()!;
            _steamContent = _steamClient.GetHandler<SteamContent>()!;
            _steamCloud = _steamClient.GetHandler<SteamCloud>()!;
            _steamUnifiedMessages = _steamClient.GetHandler<SteamUnifiedMessages>()!;
            _steamPublishedFile = _steamUnifiedMessages.CreateService<IPublishedFile>();
            _callbackManager.Subscribe<SteamClient.ConnectedCallback>(OnConnectedAsync);
            _callbackManager.Subscribe<SteamClient.DisconnectedCallback>(OnDisconnected);
            _callbackManager.Subscribe<SteamUser.LoggedOnCallback>(OnLoggedOn);
            _callbackManager.Subscribe<SteamUser.LoggedOffCallback>(OnLoggedOff);
            _callbackManager.Subscribe<SteamApps.LicenseListCallback>(OnLicenseList);
            Connect();
        }

        public async Task LoginAsync(CancellationToken cancellationToken)
        {
            await Task.Run(() =>
            {
                while (!cancellationToken.IsCancellationRequested && !_isLoggedOn)
                    _callbackManager.RunWaitCallbacks();
            }, CancellationToken.None);
        }

        private async void OnLoggedOn(SteamUser.LoggedOnCallback loggedOn)
        {
            switch (loggedOn.Result)
            {
                case EResult.AccountLoginDeniedNeedTwoFactor:
                    Disconnect(false);
                    _logOnDetails.TwoFactorCode = await _steamAuthenticator.GetDeviceCodeAsync(false);
                    Connect();
                    break;
                case EResult.AccountLogonDenied:
                    Disconnect(false);
                    _logOnDetails.AuthCode = await _steamAuthenticator.GetEmailCodeAsync(loggedOn.EmailDomain!, false);
                    Connect();
                    break;
                case EResult.InvalidPassword when _downloadConfig.RememberPassword && _logOnDetails.AccessToken is not null:
                    Disconnect(false);
                    (_logOnDetails.Username, _logOnDetails.Password, _logOnDetails.ShouldRememberPassword) = await _steamAuthenticator.ProvideLoginDetailsAsync();
                    Connect();
                    break;
                case EResult.TryAnotherCM:
                    Reconnect();
                    break;
                case EResult.ServiceUnavailable:
                    Disconnect(false);
                    break;
                case EResult.OK:
                    _isLoggedOn = true;
                    break;
                case not EResult.OK:
                    Disconnect(true);
                    break;
            }
        }

        private void OnLicenseList(SteamApps.LicenseListCallback licenseList)
        {
            if (licenseList.Result != EResult.OK)
                return;
            _licenseList = licenseList.LicenseList;
        }

        public SteamClient SteamClient => _steamClient;

        public SteamApps SteamApps => _steamApps;

        public SteamContent SteamContent => _steamContent;

        public async Task<SteamApps.PICSProductInfoCallback.PICSProductInfo?> GetAppInfoAsync(uint appId)
        {
            SteamApps.PICSTokensCallback methodTokens = await _steamApps.PICSGetAccessTokens(appId, null);
            if (methodTokens.AppTokensDenied.Contains(appId))
                return null;

            SteamApps.PICSRequest request = new(appId) { AccessToken = methodTokens.AppTokens.GetValueOrDefault(appId, 0UL) };
            AsyncJobMultiple<SteamApps.PICSProductInfoCallback>.ResultSet productInfos = await _steamApps.PICSGetProductInfo(request, null);
            if (productInfos.Results is null)
                return null;

            foreach (SteamApps.PICSProductInfoCallback result in productInfos.Results)
            {
                if (result.Apps.TryGetValue(appId, out SteamApps.PICSProductInfoCallback.PICSProductInfo? productInfo))
                    return productInfo;
            }

            return null;
        }

        public async Task<Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo>?> GetPackageInfoAsync(IList<uint> packageIds)
        {
            if (packageIds.Count == 0)
                return null;

            IReadOnlyCollection<SteamApps.LicenseListCallback.License>? licences = await GetLicenseListAsync();
            if (licences is null)
                return null;

            IEnumerable<SteamApps.PICSRequest> packageRequests = packageIds.Select(id => new SteamApps.PICSRequest(id) { AccessToken = licences.FirstOrDefault(licence => licence.PackageID == id)?.AccessToken ?? 0 });
            AsyncJobMultiple<SteamApps.PICSProductInfoCallback>.ResultSet productInfos = await _steamApps.PICSGetProductInfo(Enumerable.Empty<SteamApps.PICSRequest>(), packageRequests);
            return productInfos.Results?.SelectMany(static x => x.Packages.Values).ToDictionary(static x => x.ID, static x => x);
        }

        public async Task<bool> TryRequestFreeAppLicenseAsync(uint appId)
        {
            try
            {
                SteamApps.FreeLicenseCallback response = await _steamApps.RequestFreeLicense(appId);
                return response.GrantedApps.Contains(appId);
            }
            catch (TaskCanceledException)
            {
                return false;
            }
        }

        public async Task<byte[]?> RequestDepotKeyAsync(uint depotId, uint appId = 0)
        {
            SteamApps.DepotKeyCallback response = await _steamApps.GetDepotDecryptionKey(depotId, appId);
            return response.Result != EResult.OK ? null : response.DepotKey;
        }

        public async Task<ulong> GetDepotManifestRequestCodeAsync(uint depotId, uint appId, ulong manifestId, string branch) => await _steamContent.GetManifestRequestCode(depotId, appId, manifestId, branch);

        public async Task<Dictionary<string, byte[]>?> GetAppBetaKeysAsync(uint appId, string password)
        {
            SteamApps.CheckAppBetaPasswordCallback result = await _steamApps.CheckAppBetaPassword(appId, password);
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

        public async Task<IReadOnlyCollection<SteamApps.LicenseListCallback.License>?> GetLicenseListAsync() =>
            await Task.Run(() =>
            {
                while (_licenseList is null)
                    _callbackManager.RunWaitCallbacks();
                return _licenseList;
            });

        public async Task<bool> GetAccountHasAccessAsync(uint appId, uint depotId)
        {
            if (_steamUser.SteamID is null || appId == SteamConstants.InvalidAppId)
                return false;

            IList<uint> licenseQuery;
            if (_steamUser.SteamID.AccountType == EAccountType.AnonUser)
            {
                licenseQuery = new List<uint> { 17906 };
            }
            else
            {
                IReadOnlyCollection<SteamApps.LicenseListCallback.License>? licenses = await GetLicenseListAsync();
                if (licenses?.Select(static x => x.PackageID) is not { } packageIds)
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

        private async void OnConnectedAsync(SteamClient.ConnectedCallback connected)
        {
            _isConnected = true;
            if (_logOnDetails.Username is null)
            {
                _steamUser.LogOnAnonymous();
            }
            else
            {
                if (_authSession is null)
                {
                    if (_logOnDetails is { Username: not null, Password: not null, AccessToken: null })
                    {
                        try
                        {
                            _authSession = await _steamClient.Authentication.BeginAuthSessionViaCredentialsAsync(new AuthSessionDetails
                            {
                                Username = _logOnDetails.Username,
                                Password = _logOnDetails.Password,
                                IsPersistentSession = _downloadConfig.RememberPassword,
                                GuardData = _previousGuardData,
                                Authenticator = _steamAuthenticator
                            });
                        }
                        catch (AuthenticationException)
                        {
                            (_logOnDetails.Username, _logOnDetails.Password, _logOnDetails.ShouldRememberPassword) = await _steamAuthenticator.ProvideLoginDetailsAsync();
                            Reconnect();
                            return;
                        }
                        catch (Exception)
                        {
                            Disconnect(false);
                            return;
                        }
                    }
                    else if (_logOnDetails.AccessToken is null && _downloadConfig.UseQrCode)
                    {
                        try
                        {
                            QrAuthSession session = await _steamClient.Authentication.BeginAuthSessionViaQRAsync(new AuthSessionDetails
                            {
                                IsPersistentSession = _downloadConfig.RememberPassword,
                                Authenticator = _steamAuthenticator
                            });

                            _authSession = session;

                            // Steam will periodically refresh the challenge url, so we need a new QR code.
                            session.ChallengeURLChanged = async () => await _steamAuthenticator.DisplayQrCode(session.ChallengeURL);

                            // Draw initial QR code immediately
                            await _steamAuthenticator.DisplayQrCode(session.ChallengeURL);
                        }
                        catch (Exception)
                        {
                            Disconnect(false);
                            return;
                        }
                    }
                }

                if (_authSession is not null)
                {
                    try
                    {
                        AuthPollResult result = await _authSession.PollingWaitForResultAsync();

                        if (!string.IsNullOrEmpty(result.NewGuardData))
                            _previousGuardData = result.NewGuardData;

                        _logOnDetails.Username = result.AccountName;
                        _logOnDetails.Password = null;
                        _logOnDetails.AccessToken = result.RefreshToken;

                        //AccountSettingsStore.Instance.LoginTokens[result.AccountName] = result.RefreshToken;
                        //AccountSettingsStore.Save();
                    }
                    catch (Exception)
                    {
                        Disconnect(false);
                        return;
                    }

                    _authSession = null;
                }

                _steamUser.LogOn(_logOnDetails);
            }
        }

        private void OnDisconnected(SteamClient.DisconnectedCallback disconnected)
        {
            _isConnected = false;
            if (_reconnect)
            {
                _reconnect = false;
                Connect();
            }
        }

        private void OnLoggedOff(SteamUser.LoggedOffCallback obj)
        {
            _isLoggedOn = false;
        }

        private void Connect()
        {
            _steamClient.Connect();
        }

        private void Disconnect(bool logOff)
        {
            if (logOff)
                _steamUser.LogOff();
            _steamClient.Disconnect();
        }

        private void Reconnect()
        {
            if (_isConnected)
            {
                _reconnect = true;
                _steamClient.Disconnect();
            }
            else
            {
                _steamClient.Connect();
            }
        }
    }
}
