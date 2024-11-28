using Microsoft.AspNetCore.Identity;

namespace JwtRoleAuthentication.Models;

public class ApplicationUser : IdentityUser
{
    public string RefreshToken { get; set; } = "empty test";
    public DateTime RefreshTokenExpiryTime { get; set; } = new();
}