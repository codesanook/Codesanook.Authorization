using CodeSanook.Authorization.Models;
using Jose;
using Orchard;
using Orchard.ContentManagement;
using Orchard.Localization;
using Orchard.Logging;
using Orchard.Mvc;
using Orchard.Roles.Models;
using Orchard.Security;
using Orchard.Security.Permissions;
using Orchard.Users.Models;
using System;
using System.Linq;
using System.Security.Authentication;
using System.Text.RegularExpressions;

namespace CodeSanook.Authorization.Services
{
    //https://scotch.io/tutorials/the-anatomy-of-a-json-web-token
    //https://github.com/dvsekhvalnov/jose-jwt
    //http://www.svlada.com/jwt-token-authentication-with-spring-boot/
    public class AuthorizationService : IAuthorizationService
    {
        //TODO exclude secret to configuration 
        private byte[] secretKey =
            new byte[] { 164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234 };
        private readonly IOrchardServices orchardService;
        private readonly IMembershipService membershipService;
        private readonly Orchard.Security.IAuthorizationService orchardAuthorizationService;
        private readonly IHttpContextAccessor httpContextAccessor;
        private static Regex accessTokenRegex = new Regex(@"Bearer\s+(?<accessToken>.+)", RegexOptions.Compiled);

        public AuthorizationService(
            IOrchardServices orchardService,
            IMembershipService membershipService,
            Orchard.Security.IAuthorizationService authorizationService,
            IHttpContextAccessor httpContextAccessor
            )
        {
            this.orchardService = orchardService;
            this.membershipService = membershipService;
            this.orchardAuthorizationService = authorizationService;
            this.httpContextAccessor = httpContextAccessor;
        }

        //property injection
        public ILogger Logger { get; set; }
        public Localizer T { get; set; }

        public IUser GetAuthenticatedUser()
        {
            var accessToken = GetAccessTokenFromRequest();
            var user = GetUser(accessToken);
            return user;
        }

        public void CheckAccess(Permission permission, IUser user, IContent content = null)
        {
            orchardAuthorizationService.CheckAccess(permission, user, content);
        }

        public RefreshTokenResponse CreateRefreshToken(RefreshTokenRequest request)
        {
            var user = membershipService.ValidateUser(request.Email, request.Password);
            if (user == null)
            {
                throw new AuthenticationException("email or password is incorrect");
            }

            var now = DateTime.UtcNow;
            var refreshTokenExpiration = GetUtcTimestamp(now.AddMonths(2));
            var refreshTokenClaim = new Claim()
            {
                sub = user.Email,
                scopes = new[] { Claim.ROLE_REFRESH_TOKEN },
                jti = Guid.NewGuid().ToString(),
                exp = refreshTokenExpiration
            };

            var refreshToken = JWT.Encode(
                    refreshTokenClaim,
                    secretKey,
                    JweAlgorithm.A256GCMKW,
                    JweEncryption.A256CBC_HS512);
            var accessToken = CreateAccessToken(user);

            var response = new RefreshTokenResponse()
            {
                RefreshToken = refreshToken,
                AccessToken = accessToken,
            };
            return response;
        }

        public AccessTokenResponse CreateAccessToken(AccessTokenRequest request)
        {
            var user = GetUser(request.RefreshToken);
            var accessToken = CreateAccessToken(user);
            var response = new AccessTokenResponse()
            {
                AccessToken = accessToken
            };
            return response;
        }

        private string GetAccessTokenFromRequest()
        {
            var httpContext = httpContextAccessor.Current();
            var request = httpContext.Request;
            const string headerKey = "Authorization";
            if (!request.Headers.AllKeys.Contains(headerKey))
            {
                throw new AuthenticationException("no access token");
            }

            var rawValue = request.Headers.GetValues(headerKey).First();
            var match = accessTokenRegex.Match(rawValue);
            var accessToken = match.Groups["accessToken"].Value;
            if (string.IsNullOrEmpty(accessToken))
            {
                throw new AuthenticationException("no access token");
            }
            return accessToken;
        }

        private Claim GetValidToken(string token)
        {
            try
            {
                var claim = JWT.Decode<Claim>(
                    token,
                    secretKey,
                    JweAlgorithm.A256GCMKW,
                    JweEncryption.A256CBC_HS512);

                var utcNow = DateTime.UtcNow;
                var expire = GetUtcDateTime(claim.exp);
                if (utcNow > expire)
                {
                    throw new AuthenticationException("token expire");
                }

                return claim;
            }
            catch(AuthenticationException ex)
            {
                throw;
            }
            catch (Exception ex)
            {
                this.Logger.Error(ex, ex.Message);
                throw new AuthenticationException("invalid token");
            }
        }

        private long GetUtcTimestamp(DateTime dateTime)
        {
            if (dateTime.Kind != DateTimeKind.Utc)
            {
                throw new ArgumentException("dateTime is not UTC");
            }

            var utcTime = dateTime.ToUniversalTime();
            var beginningOfTimeStamp = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            long unixTimestamp = (long)(dateTime.Subtract(beginningOfTimeStamp)).TotalSeconds;
            return unixTimestamp;
        }

        private DateTime GetUtcDateTime(long timestamp)
        {
            var now = DateTime.UtcNow;
            var beginningOfTimeStamp = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var utcNow = beginningOfTimeStamp.AddSeconds(timestamp);
            return utcNow;
        }

        private string CreateAccessToken(IUser user)
        {
            var now = DateTime.UtcNow;
            var accessTokenExpiration = GetUtcTimestamp(now.AddMinutes(30));
            var role = user.As<UserRolesPart>();
            var accessTokenClaim = new Claim()
            {
                sub = user.Email,
                scopes = role.Roles.ToArray(),//role of the current user
                jti = Guid.NewGuid().ToString(),
                exp = accessTokenExpiration
            };

            var accessToken = JWT.Encode(
                    accessTokenClaim,
                    secretKey,
                    JweAlgorithm.A256GCMKW,
                    JweEncryption.A256CBC_HS512);
            return accessToken;
        }

        private IUser GetUser(string accessToken)
        {
            var claim = GetValidToken(accessToken);
            var user = orchardService.ContentManager.Query<UserPart, UserPartRecord>()
                .Where<UserPartRecord>(u => u.Email == claim.sub)
                .List()
                .SingleOrDefault();
            if (user == null)
            {
                throw new AuthenticationException("no user with given access token");
            }

            return user;
        }
    }
}