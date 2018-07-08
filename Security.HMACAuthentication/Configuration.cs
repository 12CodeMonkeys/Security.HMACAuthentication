using Security.HMACAuthentication.Interfaces;
using System;
using System.Collections.Generic;
using System.Text;

namespace Security.HMACAuthentication
{
    public class Configuration : IConfiguration
    {
        public IHashKeyRepo HashKeyRepo => new HashKeyRepo();

        public IReplayCache ReplayCache => new ReplayCache();

        public IAuthorisationHeaderSerializer AuthorisationHeaderSerializer => new AuthorisationHeaderSerializer();

        public ISigner Signer => new Signer();
    }
}
