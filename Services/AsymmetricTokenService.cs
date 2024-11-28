using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JwtRoleAuthentication.Helpers;
using JwtRoleAuthentication.Models;
using Microsoft.IdentityModel.Tokens;

namespace JwtRoleAuthentication.Services;

public class AsymmetricTokenService : ITokenService
{
    public const int AccessTokenExpirationMinutes = 60;
    public const int RefreshTokenExpirationDays = 7;
    private readonly ILogger<AsymmetricTokenService> _logger;
    private readonly IConfiguration _configuration;
    private readonly RsaSecurityKey _privateKey;
    private readonly RsaSecurityKey _publicKey;

    public AsymmetricTokenService(ILogger<AsymmetricTokenService> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
        _privateKey = RsaKeyGenerator.GenerateOrLoadKeys();
        _publicKey = RsaKeyGenerator.LoadPublicKey();
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
        
        var rsa = (_privateKey.Rsa as RSA) ?? RSA.Create();
        var signature = rsa.SignData(
            Encoding.UTF8.GetBytes(tokenData),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );
        
        return Convert.ToBase64String(
            Encoding.UTF8.GetBytes($"{tokenData}:{Convert.ToBase64String(signature)}")
        );
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
            var signature = Convert.FromBase64String(tokenParts[2]);

            var currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (timestamp < currentTime)
                return (false, null);

            var tokenData = $"{userId}:{timestamp}";
            var rsa = (_publicKey.Rsa as RSA) ?? RSA.Create();
            
            var isValid = rsa.VerifyData(
                Encoding.UTF8.GetBytes(tokenData),
                signature,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1
            );

            return (isValid, userId);
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
            return new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
            };
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    private SigningCredentials CreateSigningCredentials() =>
        new SigningCredentials(_privateKey, SecurityAlgorithms.RsaSha256);
}