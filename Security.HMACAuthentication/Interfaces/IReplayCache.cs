namespace Security.HMACAuthentication.Interfaces
{
    public interface IReplayCache
    {
        bool IsReplayRequest(string nonce, string epoch);
    }
}
