using System;
using System.Collections.Generic;
using System.Text;

namespace Security.HMACAuthentication.Interfaces
{
    public interface IConfiguration
    {
        IHashKeyRepo HashKeyRepo { get; }

        IReplayCache ReplayCache { get; }

        IAuthorisationHeaderSerializer AuthorisationHeaderSerializer { get; }

        ISigner Signer { get; }
    }
}
