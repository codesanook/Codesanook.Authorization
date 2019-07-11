using System.Security.Authentication;

namespace Codesanook.Authorization
{
    public static class AuthenticationExceptionHelper
    {
        private const string customErrorMessageKey = "customErrorMessageKey";

        public static string GetCustomErrorMessage(this AuthenticationException authenticationException)
        {
            return authenticationException.Data.Contains(customErrorMessageKey)
                ? authenticationException.Data[customErrorMessageKey] as string
                : null;
        }

        public static void SetCustomErrorMessage(this AuthenticationException authenticationException, string message)
        {
            authenticationException.Data[customErrorMessageKey] = message;
        }
    }
}