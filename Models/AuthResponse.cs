namespace JwtRoleAuthentication.Models;

public class AuthResponse
{
    public string? Username { get; set; }
    public string? Email { get; set; }
    public string? Token { get; set; }
    public string? RefreshToken { get; set; }
    
    public DateTime AccessTokenExpiryTime { set; get; }
    public DateTime ExpirationTokenExpiryTime { get; set; }
}