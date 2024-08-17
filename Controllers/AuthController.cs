using LearnAuthenticationJWT.ActionFilters;
using LearnAuthenticationJWT.DataContexts;
using LearnAuthenticationJWT.Model;
using LearnAuthenticationJWT.TokenServices;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LearnAuthenticationJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly DataContext _dataContext;
        private readonly ILogger<AuthController> _logger;
        private readonly ITokenService _tokenService;

        public AuthController(IConfiguration configuration, UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager, DataContext dataContext, ITokenService tokenService, ILogger<AuthController> logger)
        {
            _configuration = configuration;
            _userManager = userManager;
            _dataContext = dataContext;
            _roleManager = roleManager;
            _tokenService = tokenService;
            _logger = logger;
        }
        [HttpPost("register-user")]
        public async Task<ActionResult> Register([FromBody] UserDto userrq)
        {
            if (String.IsNullOrEmpty(userrq.UserName) || String.IsNullOrEmpty(userrq.Password) || String.IsNullOrEmpty(userrq.Email))
            {
                return BadRequest("User Name and Password are required.");
            }
            try
            {
                var userExist = await _userManager.FindByNameAsync(userrq.UserName);
                var userMailExist = await _userManager.FindByEmailAsync(userrq.Email);

                if (userExist != null || userMailExist != null)
                {
                    return StatusCode(StatusCodes.Status409Conflict, new { Status = "Error", Message = "User already exist." });
                }

                IdentityUser user = new IdentityUser
                {

                    UserName = userrq.UserName,
                    Email = userrq.Email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                };

                var result = await _userManager.CreateAsync(user, userrq.Password);

                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "User Creation failed, check you details and try again." });
                }

                if (!await _roleManager.RoleExistsAsync(Roles.USER_ROLE))
                {
                    await _roleManager.CreateAsync(new IdentityRole(Roles.USER_ROLE));
                }


                if (await _roleManager.RoleExistsAsync(Roles.USER_ROLE))
                {
                    await _userManager.AddToRoleAsync(user, Roles.USER_ROLE);
                }


                return Ok(new { Status = "Success", Message = "User created successfully." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while registering the user.");
                return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "An unexcepted error occurred while registering the user. Please try again later." });
            }

        }

        [HttpPost("refresh")]
        [ServiceFilter(typeof(ActionFilter))]
        public async Task<ActionResult> RefreshToken2([FromBody] RefreshTokenRequest request)
        {
            try
            {
                var userName = request.UserName;

                var user = await _userManager.FindByNameAsync(userName);
                if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
                {
                    return Unauthorized();
                }

                var refreshTokenValidate = await _tokenService.ValidateRefreshTokenAsync(request.RefreshToken);

                if (refreshTokenValidate == null)
                {
                    return Unauthorized("Invalid or expired refresh token.");
                }

                var token = await _tokenService.CreateTokenAsync(user, _tokenService.ExtractTokenFromRequest(Request));
                string refreshTokenst = await _tokenService.GenerateAndStoreRefreshTokenAsync(user.Id, request.RefreshToken);

                return Ok(new { token, refreshTokenst });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while refreshing the token.");
                return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "Refreshing the token failed." });
            }
        }

        [HttpPost("register-admin")]
        //[Authorize(Policy = "AdminOnly")]

        //[ServiceFilter(typeof(ActionFilter))]
        public async Task<ActionResult> RegisterAdmin([FromBody] UserDto userrq)
        {
            if (String.IsNullOrEmpty(userrq.UserName) || String.IsNullOrEmpty(userrq.Password) || String.IsNullOrEmpty(userrq.Email))
            {
                return BadRequest("User Name and Password are required.");
            }
            try
            {
                var adminExist = await _userManager.FindByNameAsync(userrq.UserName);
                var adminEmailExist = await _userManager.FindByEmailAsync(userrq.Email);

                if (adminExist != null || adminEmailExist != null)
                {
                    return StatusCode(StatusCodes.Status409Conflict, new { Status = "Error", Message = "User already exist." });
                }

                IdentityUser admin = new IdentityUser
                {

                    UserName = userrq.UserName,
                    Email = userrq.Email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                };

                var result = await _userManager.CreateAsync(admin, userrq.Password);

                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "Admin Creation failed, check you details and try again." });
                }

                if (!await _roleManager.RoleExistsAsync(Roles.ADMIN_ROLE))
                {
                    await _roleManager.CreateAsync(new IdentityRole(Roles.ADMIN_ROLE));
                }
                if (!await _roleManager.RoleExistsAsync(Roles.USER_ROLE))
                {
                    await _roleManager.CreateAsync(new IdentityRole(Roles.USER_ROLE));
                }

                if (await _roleManager.RoleExistsAsync(Roles.ADMIN_ROLE))
                {
                    await _userManager.AddToRoleAsync(admin, Roles.ADMIN_ROLE);
                }

                if (await _roleManager.RoleExistsAsync(Roles.USER_ROLE))
                {
                    await _userManager.AddToRoleAsync(admin, Roles.USER_ROLE);
                }
                return Ok(new { Status = "Success", Message = "Admin created successfully." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while registering the admin.");
                return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "An unexcepted error occurred while registering the admin. Please try again later." });
            }

        }


        [HttpPost("login")]
        public async Task<ActionResult> Login([FromBody] LoginDto requiest)
        {
            if (String.IsNullOrEmpty(requiest.UserName) || String.IsNullOrEmpty(requiest.Password))
            {
                return BadRequest("User Name and Password are required.");
            }

            try
            {
                var userss = await _userManager.FindByNameAsync(requiest.UserName);

                if (userss != null && await _userManager.CheckPasswordAsync(userss, requiest.Password))
                {


                    string token = await _tokenService.CreateTokenAsync(userss, _tokenService.ExtractTokenFromRequest(Request));

                    string refreshTokenst = await _tokenService.GenerateAndStoreRefreshTokenAsync(userss.Id, _tokenService.ExtractTokenFromRequest(Request));

                    return Ok(new { token, refreshTokenst });
                }

                return Unauthorized("Invalid username or password.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while login.");
                return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "An unexcepted error occurred while login. Please try again later." });
            }


        }
        //Currently not in use//
        private ClaimsPrincipal getPrincipalFromExpiredToken(string token)
        {
            var tokenhandler = new JwtSecurityTokenHandler();

            var jwtSettings = _configuration.GetSection("JWT");
            var Audiences = jwtSettings.GetSection("Audiences").Get<string[]>();
            var issuer = jwtSettings["Issuer"];
            var securityKey = jwtSettings["Token"];

            var validationParemeter = new TokenValidationParameters()
            {

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey!)),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false,
                ValidIssuer = issuer,
                ValidAudiences = Audiences,
                RequireExpirationTime = true

            };

            try
            {
                return tokenhandler.ValidateToken(token, validationParemeter, out _);
            }
            catch (Exception ex)
            {
                throw new SecurityTokenException("Invalid Token", ex);
            }


        }


    }
}