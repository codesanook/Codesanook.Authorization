using Orchard.Localization;
using Orchard;
using System.Web.Http;
using CodeSanook.Authentication.Models;
using System.Net.Http;
using System.Net;
using Orchard.Security;
using System.Security.Authentication;

namespace CodeSanook.Authentication.Controllers
{
    public class AuthenticationController : ApiController
    {
        private readonly IOrchardServices orchardService;
        private readonly IMembershipService membershipService;
        private readonly Services.IAuthenticationService authenticationService;

        public Localizer T { get; set; }

        public AuthenticationController(
            IOrchardServices orchardService,
            IMembershipService membershipService,
            Services.IAuthenticationService authenticationService
            )
        {
            this.orchardService = orchardService;
            this.membershipService = membershipService;
            this.authenticationService = authenticationService;
            T = NullLocalizer.Instance;
        }

        [ActionName("refresh-token")]
        [HttpPost]
        public RefreshTokenResponse GetRefreshToken(RefreshTokenRequest request)
        {
            try
            {
                return authenticationService.CreateRefreshToken(request);
            }
            catch (AuthenticationException ex)
            {
                var msg = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    ReasonPhrase = ex.Message
                };
                throw new HttpResponseException(msg);
            }
        }

        [ActionName("access-token")]
        [HttpPost]
        public AccessTokenResponse GetAccessToken(AccessTokenRequest request)
        {
            try
            {
                return authenticationService.CreateAccessToken(request);
            }
            catch (AuthenticationException ex)
            {
                var msg = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    ReasonPhrase = ex.Message
                };
                throw new HttpResponseException(msg);
            }
        }
    }
}