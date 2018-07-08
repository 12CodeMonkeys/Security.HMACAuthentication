using Security.HMACAuthentication.Interfaces;
using System;
using System.Runtime.Caching;

namespace Security.HMACAuthentication
{
    public class ReplayCache : IReplayCache
    {
        private readonly MemoryCache _memoryCache;

        public ulong MaxRequestAge { get; set; }

        public ReplayCache() : this(300)
        {
        }

        public ReplayCache(ulong maxRequestAge)
        {
            MaxRequestAge = maxRequestAge;
            _memoryCache = new MemoryCache("ReplayCache");
        }

        public bool IsReplayRequest(string nonce, string posixTimestamp)
        {
            if (_memoryCache == null)
                return false;

            if (_memoryCache.Contains(nonce))
                return true;

            if (CalculateRequestAge(posixTimestamp) > MaxRequestAge)
                return true;

            _memoryCache.Add(nonce, posixTimestamp, DateTimeOffset.UtcNow.AddSeconds(MaxRequestAge));

            return false;
        }

        public static ulong CalculateRequestAge(string posixTimestamp)
        {
            if (posixTimestamp == null)
                throw new ArgumentNullException();

            DateTime epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan currentTs = DateTime.UtcNow - epochStart;

            var serverTotalSeconds = Convert.ToUInt64(currentTs.TotalSeconds);
            var requestTotalSeconds = Convert.ToUInt64(posixTimestamp);

            var tMin = Math.Min(serverTotalSeconds, requestTotalSeconds);
            var tMax = Math.Max(serverTotalSeconds, requestTotalSeconds);

            return tMax - tMin;
        }
    }
}
