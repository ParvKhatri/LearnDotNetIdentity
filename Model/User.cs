using Microsoft.AspNetCore.Identity;

namespace LearnAuthenticationJWT.Model
{
 

    public class RefreshTokenRequest
    {
        public string UserName { get; set; }
        public string RefreshToken { get; set; }
        public string Password { get; set; }
    }
    /// <summary>
    /// Entity associated with refresh token.
    /// </summary>
    public class RefreshToken
    {
        public Guid Id { get; set; }  
        public string Token { get; set; }
        public DateTime Expire { get; set; }

        public string UserId { get; set; }
        public IdentityUser User { get; set; }
    }
    /// <summary>
    /// Entity associated with access token (Token).
    /// </summary>
    public class AccessToken
    {
        public Guid Id { get; set; }
        public string Token { get; set; }
        public DateTime Expire { get; set; }

        public string UserId { get; set; }
        public IdentityUser User { get; set; }
    }
}
