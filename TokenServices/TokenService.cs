using LearnAuthenticationJWT.DataContexts;
using LearnAuthenticationJWT.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Transactions;

namespace LearnAuthenticationJWT.TokenServices
{
    /// <summary>
    /// Provides services for handling JWT and refresh tokens, including creation, validation,
    /// and storage of tokens. This service interacts with the database to manage tokens
    /// and ensures their validity and security within the application.
    /// </summary>
    public interface ITokenService
    {
        /// <summary>
        /// Checks if the token is available in the request and is valid.
        /// </summary>
        /// <param name="request">The HttpRequest object containing the token.</param>
        /// <returns>True if the token is valid, otherwise false.</returns>
        public Task<bool> CheckAvialableAndValidAsync(HttpRequest request);
        /// <summary>
        /// Extract token form HTTPRequest.
        /// </summary>
        /// <param name="request">The HttpRequest object containing the token.</param>
        /// <returns>Token string if the token is valid avialable, otherwise, an empty string.</returns>
        public string ExtractTokenFromRequest(HttpRequest request);
        /// <summary>
        /// Creates a new JWT token for the specified user, and optionally removes the old token if provided.
        /// </summary>
        /// <param name="user">The <see cref="IdentityUser"/> for whom the token is being created.</param>
        /// <param name="tokenOld">Optional. The old token string to be removed before creating a new one. If not provided, a new token is created without removing any existing tokens.</param>
        /// <returns>A task that represents the asynchronous operation, containing the new JWT token string.</returns>
        public Task<string> CreateTokenAsync(IdentityUser user, string tokenOld = "");
        /// <summary>
        /// Validates the provided refresh token to ensure it is valid and not expired.
        /// </summary>
        /// <param name="token">The refresh token to validate.</param>
        /// <returns>A task that represents the asynchronous operation. 
        /// The task result contains the <see cref="RefreshToken"/> if the token is valid; otherwise, it returns <c>null</c>.</returns>
        public Task<RefreshToken> ValidateRefreshTokenAsync(string token);
        /// <summary>
        /// Creates a new refresh token, stores it in the database, and optionally removes the old refresh token if provided.
        /// </summary>
        /// <param name="userId">The ID of the user for whom the refresh token is being generated.</param>
        /// <param name="oldToken">The old refresh token to be removed, if applicable.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the new refresh token string.</returns>
        public Task<string> GenerateAndStoreRefreshTokenAsync(string userId, string oldToken = "");

        public readonly static string ADMIN = "Admin";
        public readonly static string USER = "USER";



    }

    public class TokenService : ITokenService
    {
        private readonly DataContext _db;
        private readonly IConfiguration _configuration;
        private readonly ILogger<TokenService> _logger;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public TokenService(DataContext db, IConfiguration configuration, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, ILogger<TokenService> logger)
        {
            _db = db;
            _configuration = configuration;
            _userManager = userManager;
            _roleManager = roleManager;
            _logger = logger;
        }
        public async Task<bool> CheckAvialableAndValidAsync(HttpRequest request)
        {
            _logger.LogInformation("Checking toke availability and validity.");
            var token = ExtractTokenFromRequest(request);
            if (String.IsNullOrEmpty(token) || String.IsNullOrWhiteSpace(token))
            {
                _logger.LogWarning("No token found in the request.");
                return false;
            }
            try
            {
                var result = await _db.AccessTokens.FirstOrDefaultAsync(x => x.Token == token);

                //check if request is for refresh token.
                bool isRefreshTokenRequest = request.Path.Value.Contains("api/auth/refresh", StringComparison.OrdinalIgnoreCase);

                if (result != null && (result.Expire > DateTime.UtcNow || isRefreshTokenRequest))
                {
                    _logger.LogInformation("Token is valid.");
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occur while validating the access token");
                throw;
            }
            _logger.LogInformation("Invalid or expired token.");
            return false;
        }
        public string ExtractTokenFromRequest(HttpRequest request)
        {
            if (request.Headers.ContainsKey("Authorization"))
            {
                var authorizationHeader = request.Headers["Authorization"].ToString();
                if (authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    return authorizationHeader.Substring("Bearer ".Length).Trim();
                }
            }
            return null;
        }

        public async Task<string> CreateTokenAsync(IdentityUser user, string tokenOld = "")
        {
            using var transaction = await _db.Database.BeginTransactionAsync();
            try
            {
                var oldAccessToken = await _db.AccessTokens.FirstOrDefaultAsync(x => x.UserId == user.Id || x.Token == tokenOld);
                if (oldAccessToken != null)
                {

                    _db.Remove(oldAccessToken);
                    await _db.SaveChangesAsync();
                }
                List<Claim> claims = new List<Claim>();

                claims.Add(new Claim(ClaimTypes.NameIdentifier, user.UserName));
                
                var audience = _configuration.GetSection("JWT:Audiences").Get<string[]>();
                var roles = await _userManager.GetRolesAsync(user);


                foreach (var role in roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("JWT:Token").Value!));
                var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(audience: audience[1], issuer: _configuration.GetSection("JWT:Issuer").Value, claims: claims, expires: DateTime.UtcNow.AddMinutes(5), signingCredentials: cred);
                string jwt = new JwtSecurityTokenHandler().WriteToken(token);


                AccessToken accessToken = new AccessToken()
                {
                    Token = jwt,
                    UserId = user.Id,
                    Expire = token.ValidTo,

                };
                _db.Add(accessToken);
                await _db.SaveChangesAsync();

                await transaction.CommitAsync();
                return jwt;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occur while creating the access token.");
                await transaction.RollbackAsync();
                throw;
            }


        }


        public async Task<RefreshToken> ValidateRefreshTokenAsync(string token)
        {
            try
            {
                var refreshToken = await _db.RefreshTokens.SingleOrDefaultAsync(x => x.Token == token && x.Expire > DateTime.UtcNow);
                return refreshToken!;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "An error occured while validation the refresh token.");
                throw;
            }

        }



        public async Task<string> GenerateAndStoreRefreshTokenAsync(string userId, string oldToken = "")
        {

            var refreshtoken = new RefreshToken()
            {
                Token = Guid.NewGuid().ToString(),
                Expire = DateTime.UtcNow.AddMinutes(10),
                UserId = userId,

            };
            try
            {
                var oldRefreshToken = await _db.RefreshTokens.FirstOrDefaultAsync(x => x.Token == oldToken || x.UserId == userId);
                if (oldRefreshToken != null)
                {
                    _db.Remove(oldRefreshToken);
                    await _db.SaveChangesAsync();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occur while removing the refresh token.");
                throw;
            }

            try
            {
                _db.Add(refreshtoken);
                await _db.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occur while storing the refresh token.");
                throw;
            }
            return refreshtoken.Token;
        }


    }
    /// <summary>
    /// Contains all valid roles.
    /// </summary>
    public static class Roles
    {
        public const string ADMIN_ROLE = "Admin";
        public const string USER_ROLE = "User";
    }
}