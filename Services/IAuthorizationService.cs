using CodeSanook.Authorization.Models;
using Orchard;
using Orchard.ContentManagement;
using Orchard.Security.Permissions;
using System.Net.Http;

namespace CodeSanook.Authorization.Services
{
    public interface IAuthorizationService : IDependency
    {
        RefreshTokenResponse CreateRefreshToken(RefreshTokenRequest request);
        AccessTokenResponse CreateAccessToken(AccessTokenRequest request);

        bool Authorize(string accessToken, Permission permission, IContent content = null);
        bool Authorize(Permission permission, IContent content = null);
    }
}