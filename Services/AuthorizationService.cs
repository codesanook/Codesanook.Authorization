using CodeSanook.Authorization.Models;
using CodeSanook.Common.DataType;
using CodeSanook.Common.DataTypes;
using CodeSanook.Configuration.Models;
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
        private readonly IOrchardServices orchardService;
        private readonly IMembershipService membershipService;
        private readonly Orchard.Security.IAuthorizationService orchardAuthorizationService;
        private readonly IHttpContextAccessor httpContextAccessor;
        private readonly ModuleSettingPart moduleSettingPart;
        private readonly byte[] refreshTokenSecretKey;
        private readonly byte[] accessTokenSecretKey;

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

            moduleSettingPart = this.orchardService.WorkContext.CurrentSite.As<ModuleSettingPart>();
            this.refreshTokenSecretKey = moduleSettingPart.RefreshTokenSecretKey.GetBytesFromAsciiString();
            this.accessTokenSecretKey = moduleSettingPart.AccessTokenSecretKey.GetBytesFromAsciiString();
        }

        //property injection
        public ILogger Logger { get; set; }
        public Localizer T { get; set; }

        public IUser GetAuthenticatedUser()
        {
            var accessToken = GetAccessTokenFromHeaderRequest();
            var accessTokenClaim = GetValidClaim(accessToken, accessTokenSecretKey);
            var user = GetValidUser(accessTokenClaim);
            return user;
        }

        public void CheckAccess(Permission permission, IUser user, IContent content = null)
        {
            orchardAuthorizationService.CheckAccess(permission, user, content);
        }

        public TokenResponse CreateRefreshTokenResponse(RefreshTokenRequest request)
        {
            var user = ValidateUser(request.Email, request.Password);
            if (user == null)
            {
                throw new AuthenticationException("email or password is incorrect");
            }
            return CreateTokenResponse(user);
        }

        public TokenResponse CreateAccessTokenResponse(AccessTokenRequest request)
        {
            var refreshTokenClaim = GetValidClaim(request.RefreshToken, refreshTokenSecretKey);
            var user = GetValidUser(refreshTokenClaim);
            var authorizationPart = user.As<AuthorizationPart>();
            if (string.Compare(refreshTokenClaim.jti, authorizationPart.RefreshTokenId.ToString(), StringComparison.OrdinalIgnoreCase) != 0)
            {
                throw new AuthenticationException("A refresh token id does not match, user may revoke a refresh token");
            }

            return CreateTokenResponse(user);
        }

        private TokenResponse CreateTokenResponse(IUser user)
        {
            var refreshToken = CreateRefreshToken(user);
            var accessToken = CreateAccessToken(user);
            var response = new TokenResponse()
            {
                RefreshToken = refreshToken,
                AccessToken = accessToken,
                UserId = user.Id
            };
            return response;
        }

        private string CreateRefreshToken(IUser user)
        {
            var now = DateTime.UtcNow;
            var refreshTokenExpiration = now.AddDays(moduleSettingPart.RefreshTokenExpireInDays)
               .GetUtcTimestamp();
            var refreshTokenId = Guid.NewGuid();
            var refreshTokenClaim = new Claim()
            {
                sub = user.Email,
                scopes = new[] { Claim.ROLE_REFRESH_TOKEN },
                exp = refreshTokenExpiration,
                jti = refreshTokenId.ToString()
            };

            var authorizationPart = user.As<AuthorizationPart>();
            authorizationPart.RefreshTokenId = refreshTokenId;

            return EncryptedClaim(refreshTokenClaim, refreshTokenSecretKey);
        }

        private string CreateAccessToken(IUser user)
        {
            var now = DateTime.UtcNow;
            var accessTokenExpiration = now.AddMinutes(moduleSettingPart.AccessTokenExpireInMinutes)
                    .GetUtcTimestamp();
            var role = user.As<UserRolesPart>();
            var accessTokenClaim = new Claim()
            {
                sub = user.Email,
                scopes = role.Roles.ToArray(),//role of the current user
                jti = Guid.NewGuid().ToString(),
                exp = accessTokenExpiration
            };

            return EncryptedClaim(accessTokenClaim, accessTokenSecretKey);
        }

        private string GetAccessTokenFromHeaderRequest()
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

        private Claim GetValidClaim(string token, byte[] secretKey)
        {
            try
            {
                var claim = JWT.Decode<Claim>(token,
                    secretKey,
                    JweAlgorithm.A256GCMKW,
                    JweEncryption.A256CBC_HS512);

                var utcNow = DateTime.UtcNow;
                var expire = claim.exp.GetUtcDateTime();
                if (utcNow > expire)
                {
                    throw new AuthenticationException("token expire");
                }

                return claim;
            }
            catch (AuthenticationException ex)
            {
                throw;
            }
            catch (Exception ex)
            {
                this.Logger.Error(ex, ex.Message);
                throw new AuthenticationException("invalid token");
            }
        }

        private string EncryptedClaim(Claim claim, byte[] secretKey)
        {
            var token = JWT.Encode(
                claim,
                secretKey,
                JweAlgorithm.A256GCMKW,
                JweEncryption.A256CBC_HS512);
            return token;
        }

        public IUser ValidateUser(string email, string password)
        {
            if (string.IsNullOrEmpty(email))
            {
                throw new AuthenticationException($"validate user error because email is null or empty");
            }

            var user = GetValidUser(email);
            return membershipService.ValidateUser(email, password);
        }

        private IUser GetValidUser(Claim claim)
        {
            return GetValidUser(claim.sub);
        }

        private IUser GetValidUser(string email)
        {
            var lowerEmail = email.ToLower();
            var user = orchardService.ContentManager.Query<UserPart, UserPartRecord>()
                .Where<UserPartRecord>(u => u.Email == lowerEmail)
                .List()
                .SingleOrDefault();
            if (user == null)
            {
                throw new AuthenticationException($"no user with email {lowerEmail}");
            }

            if (user.EmailStatus != UserStatus.Approved)
            {
                throw new AuthenticationException($"user email {lowerEmail} does not activate by email");
            }

            if (user.RegistrationStatus != UserStatus.Approved)
            {
                throw new AuthenticationException($"user email {lowerEmail} is deactivated");
            }

            return user;
        }
    }
}