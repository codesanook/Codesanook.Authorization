using Orchard.Security;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Web.Http.Filters;

namespace Codesanook.Authorization
{
    public class AuthenticationExceptionAttribute : ExceptionFilterAttribute
    {
        public override void OnException(HttpActionExecutedContext actionExecutedContext)
        {
            var exception = actionExecutedContext.Exception;
            if (exception is AuthenticationException)
            {
                var authenticationException = exception as AuthenticationException;
                var customErrorMessage = authenticationException.GetCustomErrorMessage();

                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    ReasonPhrase = authenticationException.GetType().Name,
                    Content = !string.IsNullOrEmpty(customErrorMessage)
                        ? new StringContent(customErrorMessage)
                        : new StringContent(authenticationException.Message)
                };
                actionExecutedContext.Response = response;
                actionExecutedContext.Exception = null;
            }
            else if (exception is OrchardSecurityException)
            {
                var ex = exception as OrchardSecurityException;
                var message = $"invalid permission '{ex.PermissionName}', userId {ex.User.Id}, content {ex.Content?.ContentItem.ContentType}";
                var response = new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    ReasonPhrase = message
                };
                actionExecutedContext.Response = response;
                actionExecutedContext.Exception = null;
            }
        }
    }
}
