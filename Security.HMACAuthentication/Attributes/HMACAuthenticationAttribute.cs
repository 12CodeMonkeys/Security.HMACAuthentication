using Security.HMACAuthentication.Interfaces;
using System;
using System.Net.Http.Headers;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Filters;
using System.Web.Http.Results;

namespace Security.HMACAuthentication.Attributes
{
    public class HMACAuthenticationAttribute : Attribute, IAuthenticationFilter
    {
        private readonly Authorization _authorization;
        private readonly IConfiguration _configuration;

        public HMACAuthenticationAttribute()
        {
            _configuration = new Configuration();
            _authorization = new Authorization(_configuration);
        }

        public bool AllowMultiple => false;

        public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            var req = context.Request;

            if (context.Request.Headers.Authorization != null &&
                _configuration.AuthorisationHeaderSerializer.AuthenticationScheme.Equals(req.Headers.Authorization.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                var authHeader = new AuthorizationHeader();
                var isValid = _authorization.AuthenticateAsync(context.Request, authHeader).Result;

                if (isValid)
                {
                    var currentPrincipal = new GenericPrincipal(new GenericIdentity(authHeader.APPId), null);
                    context.Principal = currentPrincipal;
                }
                else
                {
                    context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0], context.Request);
                }
            }
            else
            {
                context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0], context.Request);
            }

            return Task.FromResult(0);
        }

        
        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
    }
}
