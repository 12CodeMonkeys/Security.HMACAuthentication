namespace Security.HMACAuthentication.Interfaces
{
    public interface IAuthorisationHeaderSerializer
    {
        string Serialize(IAuthorizationHeader authorisationHeader);

        IAuthorizationHeader Deserialize(string authorisationHeader);

        string AuthenticationScheme { get; }
    }
}
