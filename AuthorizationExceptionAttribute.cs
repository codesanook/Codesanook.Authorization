using Orchard.Security;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Web.Http.Filters;

namespace CodeSanook.Authorization
{
    public class AuthorizationExceptionAttribute : ExceptionFilterAttribute
    {
        public override void OnException(HttpActionExecutedContext actionExecutedContext)
        {
            var exception = actionExecutedContext.Exception;
            if (exception is AuthenticationException)
            {
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    ReasonPhrase = exception.Message,
                };
                actionExecutedContext.Response = response;
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
            }
        }
    }
}