namespace CodeSanook.Authorization.Models
{
    /*
    Registered Claims
    Claims that are not mandatory whose names are reserved for us. These include:
    iss: The issuer of the token
    sub: The subject of the token
    aud: The audience of the token
    exp: This will probably be the registered claim most often used. This will define the expiration in NumericDate value. The expiration MUST be after the current date/time.
    nbf: Defines the time before which the JWT MUST NOT be accepted for processing
    iat: The time the JWT was issued. Can be used to determine the age of the JWT
    jti: Unique identifier for the JWT. Can be used to prevent the JWT from being replayed. 
    This is helpful for a one time use token.
    */

    public class Claim
    {
        public const string ROLE_REFRESH_TOKEN = "ROLE_REFRESH_TOKEN";
        public string sub { get; set; }
        public string[] scopes { get; set; }
        /// <summary>
        /// Claim Id
        /// </summary>
        public string jti { get; set; }
        public long exp { get; set; }
    }
}