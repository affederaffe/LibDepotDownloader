using System.Collections.Generic;

using ProtoBuf;


namespace LibDepotDownloader
{
    [ProtoContract]
    public class AccountSettingsStore
    {
        [ProtoMember(1, IsRequired = false)]
        public Dictionary<string, byte[]>? SentryData { get; }

        [ProtoMember(2, IsRequired = false)]
        public Dictionary<string, string>? LoginTokens { get; }
    }
}
