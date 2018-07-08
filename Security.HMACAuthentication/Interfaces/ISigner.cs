using System.Net.Http;
using System.Threading.Tasks;

namespace Security.HMACAuthentication.Interfaces
{
    public interface ISigner
    {
        string Sign(string url, string httpMethod, byte[] requestBody, IAuthorizationHeader authHeader, IHashKeys hashKeys);

        Task<string> SignAsync(HttpRequestMessage request, IAuthorizationHeader authHeader, IHashKeys hashKeys);
    }
}
