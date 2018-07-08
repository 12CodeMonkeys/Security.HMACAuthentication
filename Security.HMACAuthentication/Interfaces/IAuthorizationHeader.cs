namespace Security.HMACAuthentication.Interfaces
{
    public interface IAuthorizationHeader
    {
        string APPId { get; }

        string Signature { get; }

        string Nonce { get; }

        string Epoch { get; }
    }
}
