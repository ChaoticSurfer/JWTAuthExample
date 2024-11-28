using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JwtRoleAuthentication.Models;
using Microsoft.IdentityModel.Tokens;

namespace JwtRoleAuthentication.Services;

public class TokenService
{
    public const int AccessTokenExpirationMinutes = 60;
    public const int RefreshTokenExpirationDays = 7;
    private readonly ILogger<TokenService> _logger;
    private readonly IConfiguration _configuration;

    public TokenService(ILogger<TokenService> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    public string CreateAccessToken(ApplicationUser user)
    {
        var expiration = DateTime.UtcNow.AddMinutes(AccessTokenExpirationMinutes);
        var token = CreateJwtToken(
            CreateClaims(user),
            CreateSigningCredentials(),
            expiration
        );
        var tokenHandler = new JwtSecurityTokenHandler();
        
        _logger.LogInformation("JWT Token created");
        
        return tokenHandler.WriteToken(token);
    }

    public string GenerateRefreshToken(ApplicationUser user)
    {
        var timestamp = DateTimeOffset.UtcNow.AddDays(RefreshTokenExpirationDays).ToUnixTimeSeconds();
        var tokenData = $"{user.Id}:{timestamp}";
        var secret = _configuration["JwtTokenSettings:SymmetricSecurityKey"];
        
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(tokenData));
        var signature = Convert.ToBase64String(hash);
        
        var refreshToken = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{tokenData}:{signature}"));
        return refreshToken;
    }

    public (bool isValid, string userId) ValidateRefreshToken(string refreshToken)
    {
        try
        {
            var tokenBytes = Convert.FromBase64String(refreshToken);
            var tokenParts = Encoding.UTF8.GetString(tokenBytes).Split(':');
            
            if (tokenParts.Length != 3)
                return (false, null);

            var userId = tokenParts[0];
            var timestamp = long.Parse(tokenParts[1]);
            var providedSignature = tokenParts[2];

            var currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (timestamp < currentTime)
                return (false, null);

            var tokenData = $"{userId}:{timestamp}";
            var secret = _configuration["JwtTokenSettings:SymmetricSecurityKey"];
            
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(tokenData));
            var computedSignature = Convert.ToBase64String(hash);

            return (providedSignature == computedSignature, userId);
        }
        catch
        {
            return (false, null);
        }
    }

    private JwtSecurityToken CreateJwtToken(List<Claim> claims, SigningCredentials credentials,
        DateTime expiration) =>
        new(
            _configuration["JwtTokenSettings:ValidIssuer"],
            _configuration["JwtTokenSettings:ValidAudience"],
            claims,
            expires: expiration,
            signingCredentials: credentials
        );

    private List<Claim> CreateClaims(ApplicationUser user)
    {        
        try
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
            };
            
            return claims;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    private SigningCredentials CreateSigningCredentials()
    {
        var symmetricSecurityKey = _configuration["JwtTokenSettings:SymmetricSecurityKey"];

        return new SigningCredentials(
            new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(symmetricSecurityKey)
            ),
            SecurityAlgorithms.HmacSha256
        );
    }
}