using CodeSanook.Authentication.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Xunit;

namespace CodeSanook.Authentication.Tests.Services
{
    public class AuthenticationServiceTests
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