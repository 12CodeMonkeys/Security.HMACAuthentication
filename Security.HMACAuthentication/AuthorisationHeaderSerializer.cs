using Security.HMACAuthentication.Interfaces;

namespace Security.HMACAuthentication
{
    public class AuthorisationHeaderSerializer : IAuthorisationHeaderSerializer
    {
        public string Serialize(IAuthorizationHeader authorisationHeader)
        {
            return $"{authorisationHeader.APPId}:{authorisationHeader.Signature}:{authorisationHeader.Nonce}:{authorisationHeader.Epoch}";
        }

        public IAuthorizationHeader Deserialize(string authorisationHeader)
        {

            if (string.IsNullOrWhiteSpace(authorisationHeader))
                return new AuthorizationHeader();

            var parameters = authorisationHeader.Split(':');

            if (parameters.Length != 4)
                return new AuthorizationHeader();

            return new AuthorizationHeader { APPId = parameters[0], Signature = parameters[1], Nonce = parameters[2], Epoch = parameters[3] };
        }

        public string AuthenticationScheme  => "amx";
    }
}
