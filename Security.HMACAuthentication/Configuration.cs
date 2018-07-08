using Security.HMACAuthentication.Interfaces;
using System;

namespace Security.HMACAuthentication
{
    public class Configuration : IConfiguration
    {
        public IHashKeyRepo HashKeyRepo => throw new NotImplementedException();

        public IReplayCache ReplayCache => new ReplayCache();

        public IAuthorisationHeaderSerializer AuthorisationHeaderSerializer => new AuthorisationHeaderSerializer();

        public ISigner Signer => new Signer();
    }
}
