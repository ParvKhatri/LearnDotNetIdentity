using System.ComponentModel.DataAnnotations;

namespace LearnAuthenticationJWT.Model
{    /// <summary>
     /// Registration parameters
     /// </summary>
    public class UserDto
    {
        [MinLength(3, ErrorMessage = "UserName must be at least 3 characters long.")]
        public required string UserName { get; set; }
        [MinLength(8, ErrorMessage = "Password must be at least 8 characters long.")]
        [MaxLength(55, ErrorMessage = "Password must be at Most 55 characters long.")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@$%&?*])[A-Za-z\d@$%&*?!]{8,}$",
            ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")]
        public required string Password { get; set; }
        [Compare("Password", ErrorMessage = "Passwords do not match.")]
        public required string ConfirmPassword { get; set; }

        [EmailAddress(ErrorMessage ="Invalid email address format.")]
        public required  string Email { get; set; }
    }

    /// <summary>
    /// Login parameters
    /// </summary>
    public class LoginDto
    {
        [MinLength(3,ErrorMessage ="UserName must be at least 3 characters long.")]
        public required string UserName { get; set; }
        [MinLength(8,ErrorMessage ="Password must be at least 8 characters long.")]
        public required string Password { get; set; }
     }
}
