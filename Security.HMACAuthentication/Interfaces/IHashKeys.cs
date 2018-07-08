namespace Security.HMACAuthentication.Interfaces
{
    public interface IHashKeys
    {
        string APPId { get; }

        string ApiKey { get; }

        string HashAlgorithm { get; }

        string HmacAlgorithm { get; }

        string UserId { get; }
    }
}
