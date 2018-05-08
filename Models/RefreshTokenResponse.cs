namespace CodeSanook.Authorization.Models
{
    public class RefreshTokenResponse
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; } 
        public int UserId { get; set; }
    }
}