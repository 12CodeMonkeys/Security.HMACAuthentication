namespace Security.HMACAuthentication.Interfaces
{
    public interface IHashKeyRepo
    {
        IHashKeys FindByAPPIId(string APPIId);
    }
}
