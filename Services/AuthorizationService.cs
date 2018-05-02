using CodeSanook.Authentication.Models;
using Jose;
using Orchard;
using Orchard.ContentManagement;
using Orchard.Roles.Models;
using Orchard.Security;
using Orchard.Security.Permissions;
using Orchard.Users.Models;
using System;
using System.Linq;
using System.Net.Http;
using System.Security.Authentication;
using System.Text.RegularExpressions;


namespace CodeSanook.Authentication.Services
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
        private readonly Orchard.Security.IAuthorizationService authorizationService;


        private static Regex accessTokenRegex = new Regex(@"Bearer\s+(?<accessToken>.+)", RegexOptions.Compiled);

        public AuthorizationService(
            IOrchardServices orchardService,
            IMembershipService membershipService,
            Orchard.Security.IAuthorizationService authorizationService
            )
        {
            this.orchardService = orchardService;
            this.membershipService = membershipService;
            this.authorizationService = authorizationService;
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
            var claim = ValidateRefreshToken(request.RefreshToken);
            var email = claim.sub;
            var user = orchardService.ContentManager.Query<UserPart, UserPartRecord>()
                .Where<UserPartRecord>(u => u.Email == email)
                .List()
                .Single();

            var accessToken = CreateAccessToken(user);

            var response = new AccessTokenResponse()
            {
                AccessToken = accessToken
            };
            return response;
        }

        public bool Authorize(HttpRequestMessage request, Permission permission, IContent content)
        {
            const string headerKey = "Authorization";
            if (!request.Headers.Contains(headerKey))
            {
                return false;
            }

            var rawValue = request.Headers.GetValues(headerKey).First();
            var match = accessTokenRegex.Match(rawValue);
            var accessToken = match.Groups["accessToken"].Value;
            if (string.IsNullOrEmpty(accessToken))
            {
                return false;
            }
            return Authorize(accessToken, permission, content);
        }


        public bool Authorize(string accessToken, Permission permission, IContent content)
        {
            var cliam = this.GetCliam(accessToken);
            var user = orchardService.ContentManager.Query<UserPart, UserPartRecord>()
                .Where<UserPartRecord>(u => u.Email == cliam.sub)
                .List()
                .Single();
            return authorizationService.TryCheckAccess(permission, user, content);
        }

        private Claim ValidateRefreshToken(string refreshToken)
        {
            try
            {
                var claim = JWT.Decode<Claim>(refreshToken, secretKey, JweAlgorithm.A256GCMKW, JweEncryption.A256CBC_HS512);

                var utcNow = DateTime.UtcNow;
                var expire = GetUtcDateTime(claim.exp);

                if (utcNow > expire)
                {
                    throw new AuthenticationException("refresh token expire");
                }
                return claim;
            }
            catch (Exception)
            {
                throw new AuthenticationException("invalid refresh token");
            }
        }

        private Claim GetCliam(string token)
        {
            var cliam = JWT.Decode<Claim>(token, secretKey, JweAlgorithm.A256GCMKW, JweEncryption.A256CBC_HS512);
            return cliam;
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
            var accessTokenExpiration = GetUtcTimestamp(now.AddMinutes(5));
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

        public bool Authorize(string accessToken, Permission permission)
        {
            return Authorize(accessToken, permission, null);
        }

        public bool Authorize(HttpRequestMessage request, Permission permission)
        {
            return Authorize(request, permission, null);
        }
    }
}