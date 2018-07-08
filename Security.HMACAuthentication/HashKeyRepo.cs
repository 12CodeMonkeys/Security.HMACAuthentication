using Security.HMACAuthentication.Interfaces;
using System;

namespace Security.HMACAuthentication
{
    public class HashKeyRepo : IHashKeyRepo
    {
        public IHashKeys FindByAPPIId(string APPIId)
        {
            throw new NotImplementedException();
        }
    }
}
