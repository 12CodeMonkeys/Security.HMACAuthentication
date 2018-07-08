using Security.HMACAuthentication.Interfaces;
using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;

namespace Security.HMACAuthentication
{
    public class Authorization
    {
        private readonly IConfiguration _configuration;

        public Authorization(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task<bool> AuthenticateAsync(HttpRequestMessage request, IAuthorizationHeader authHeader)
        {
            var reqUri = HttpUtility.UrlEncode(request.RequestUri.AbsoluteUri.ToLower());
            var reqMethod = request.Method.Method;
            var reqContent = await request.Content.ReadAsByteArrayAsync();

            authHeader = _configuration.AuthorisationHeaderSerializer.Deserialize(request.Headers.Authorization.Parameter);
            var hashKeys = _configuration.HashKeyRepo.FindByAPPIId(authHeader.APPId);

            return ValidateRequest(reqUri, reqMethod, reqContent, authHeader, hashKeys);
        }

        public bool ValidateRequest(string requestUrl, string requestMethod, byte[] requestContent, IAuthorizationHeader authHeader, IHashKeys hashKeys)
        {
            var encodedContent = string.Empty;

            if (_configuration.ReplayCache.IsReplayRequest(authHeader.Nonce, authHeader.Epoch))
                return false;

            var expectedSignature = _configuration.Signer.Sign(requestUrl, requestMethod, requestContent, authHeader, hashKeys);
            return (authHeader.Signature.Equals(expectedSignature, StringComparison.Ordinal));
        }
    }
}
