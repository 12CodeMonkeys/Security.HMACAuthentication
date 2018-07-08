using Security.HMACAuthentication.Interfaces;
using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Security.HMACAuthentication
{
    public class Signer : ISigner
    {
        public async Task<string> SignAsync(HttpRequestMessage request, IAuthorizationHeader authHeader, IHashKeys hashKeys)
        {
            var requestContentBase64String = string.Empty;
            var requestUrl = System.Web.HttpUtility.UrlEncode(request.RequestUri.AbsoluteUri.ToLower());
            var httpMethod = request.Method.Method;
            byte[] content = null;

            if (request.Content != null)
                content = await request.Content.ReadAsByteArrayAsync();

            return Sign(requestUrl, httpMethod, content, authHeader, hashKeys);
        }

        public string Sign(string requestUrl, string httpMethod, byte[] requestBody, IAuthorizationHeader authHeader, IHashKeys hashKeys)
        {
            var encodedContent = string.Empty;

            var hash = ComputeHash(hashKeys.HashAlgorithm, requestBody);
            if (hash != null)
                encodedContent = Convert.ToBase64String(hash);

            var data = $"{hashKeys.ApiKey}{httpMethod}{requestUrl}{authHeader.Epoch}{authHeader.Nonce}{encodedContent}";
            var calcSignature = Encoding.UTF8.GetBytes(data);

            using (var hmac = HMAC.Create(hashKeys.HmacAlgorithm))
            {
                hmac.Key = Convert.FromBase64String(hashKeys.ApiKey);
                var signatureBytes = hmac.ComputeHash(calcSignature);
                return Convert.ToBase64String(signatureBytes);
            }
        }

        public static byte[] ComputeHash(string algorithm, byte[] data)
        {
            using (var hashAlgorithm = HashAlgorithm.Create(algorithm))
            {
                byte[] hash = null;

                if (data != null && data.Length != 0)
                    hash = hashAlgorithm.ComputeHash(data);

                return hash;
            }
        }
    }
}
