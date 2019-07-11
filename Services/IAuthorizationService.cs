using Codesanook.Authorization.Models;
using Orchard;
using Orchard.ContentManagement;
using Orchard.Security;
using Orchard.Security.Permissions;

namespace Codesanook.Authorization.Services
{
    public interface IAuthorizationService : IDependency
    {
        TokenResponse CreateRefreshTokenResponse(RefreshTokenRequest request);
        TokenResponse CreateAccessTokenResponse(AccessTokenRequest request);
        void CheckAccess(Permission permission, IUser user, IContent content = null);
        IUser GetAuthenticatedUser();
        IUser ValidateUser(string email, string password);
    }
}