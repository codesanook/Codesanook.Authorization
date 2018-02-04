using CodeSanook.Authentication.Models;
using Orchard;
using Orchard.ContentManagement;
using Orchard.Security.Permissions;
using System.Net.Http;

namespace CodeSanook.Authentication.Services
{
    public interface IAuthenticationService : IDependency
    {
        RefreshTokenResponse CreateRefreshToken(RefreshTokenRequest request);
        AccessTokenResponse CreateAccessToken(AccessTokenRequest request);
        bool Authorize(string accessToken, Permission permission, IContent content);
        bool Authorize(string accessToken, Permission permission);
        bool Authorize(HttpRequestMessage request, Permission permission, IContent content);
        bool Authorize(HttpRequestMessage request, Permission permission);
    }
}