using Orchard.Localization;
using Orchard;
using System.Web.Http;
using Orchard.Security;
using Codesanook.Authorization.Models;

namespace Codesanook.Authorization.Controllers {
    public class AuthenticationController : ApiController {
        private readonly Services.IAuthorizationService authenticationService;
        public Localizer T { get; set; }

        public AuthenticationController(Services.IAuthorizationService authenticationService) {
            this.authenticationService = authenticationService;
            T = NullLocalizer.Instance;
        }

        [ActionName("refresh-token")]
        [HttpPost]
        public TokenResponse GetRefreshToken(RefreshTokenRequest request) =>
            authenticationService.CreateRefreshTokenResponse(request);

        [ActionName("access-token")]
        [HttpPost]
        public TokenResponse GetAccessToken(AccessTokenRequest request) =>
            authenticationService.CreateAccessTokenResponse(request);
    }
}
