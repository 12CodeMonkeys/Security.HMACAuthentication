using Security.HMACAuthentication.Interfaces;
using System;

namespace Security.HMACAuthentication
{
    public class AuthorizationHeader : IAuthorizationHeader
    {
        public string APPId { get; set; }

        public string Signature { get; set; }

        public string Nonce { get; set; }

        public string Epoch { get; set; }

        public AuthorizationHeader()
        {
        }

        public AuthorizationHeader(string appId)
        {
            DateTime epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan timeSpan = DateTime.UtcNow - epochStart;

            Epoch = Convert.ToUInt64(timeSpan.TotalSeconds).ToString();
            Nonce = Guid.NewGuid().ToString("N");
            APPId = appId;
        }
    }
}
