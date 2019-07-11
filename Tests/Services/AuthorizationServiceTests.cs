using Codesanook.Authorization.Models;
using Xunit;

namespace Codesanook.Authorization.Tests.Services
{
    public class AuthorizationServiceTests
    {
        [Fact]
        public void Test()
        {
            //var authenticationService = new AuthenticationService();
            var claim = new Claim()
            {
                sub = "test@mail.com",
                scopes = new[] { Claim.ROLE_REFRESH_TOKEN },
            };

            //var token = authenticationService.CreateToken(claim);
            //var result = authenticationService.GetCliam(token);
        }
    }
}