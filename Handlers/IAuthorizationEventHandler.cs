using Orchard.Events;
using Orchard.Security;
using System.Security.Authentication;

namespace Codesanook.Authorization.Handlers
{
    public interface IAuthorizationEventHandler : IEventHandler
    {
        void OnUnverifiedEmailException(AuthenticationException authenticationException, IUser user);
        void OnUnactivatedException(AuthenticationException authenticationException, IUser user);
    }
}