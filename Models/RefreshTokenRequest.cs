namespace CodeSanook.Authorization.Models
{
    public class RefreshTokenRequest
    {
        public string Email { get; set; }
        public string Password { get; set; } 
    }
}