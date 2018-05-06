using CodeSanook.Authorization.Models;
using Orchard;
using Orchard.ContentManagement;
using Orchard.Security;
using Orchard.Security.Permissions;

namespace CodeSanook.Authorization.Services
{
    public interface IAuthorizationService : IDependency
    {
        RefreshTokenResponse CreateRefreshToken(RefreshTokenRequest request);
        AccessTokenResponse CreateAccessToken(AccessTokenRequest request);
        void CheckAccess(Permission permission, IUser user, IContent content = null);
        IUser GetAuthenticatedUser();
        IUser ValidateUser(string email, string password);
    }
}