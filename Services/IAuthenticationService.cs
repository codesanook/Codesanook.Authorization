using CodeSanook.Authentication.Models;
using Orchard;
using Orchard.ContentManagement;
using Orchard.Security.Permissions;

namespace CodeSanook.Authentication.Services
{
    public interface IAuthenticationService : IDependency
    {
        RefreshTokenResponse CreateRefreshToken(RefreshTokenRequest request);
        AccessTokenResponse CreateAccessToken(AccessTokenRequest request);
        bool Authorize(string accessToken, Permission permission, IContent content);
    }
}