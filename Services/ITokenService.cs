namespace JwtRoleAuthentication.Services;

using JwtRoleAuthentication.Models;


public interface ITokenService
{
    string CreateAccessToken(ApplicationUser user);
    string GenerateRefreshToken(ApplicationUser user);
    (bool isValid, string userId) ValidateRefreshToken(string refreshToken);
}