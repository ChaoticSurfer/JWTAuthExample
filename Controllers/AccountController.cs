using JwtRoleAuthentication.Data;
using JwtRoleAuthentication.Models;
using JwtRoleAuthentication.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;


namespace JwtRoleAuthentication.Controllers;

[ApiController]
[Route("/api/[controller]")]
public class AccountController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly ITokenService _tokenService;

    public AccountController(UserManager<ApplicationUser> userManager, ApplicationDbContext context,
        ITokenService tokenService, ILogger<AccountController> logger)
    {
        _userManager = userManager;
        _context = context;
        _tokenService = tokenService;
    }

    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> Register(RegistrationRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = new ApplicationUser 
        { 
            UserName = request.Username, 
            Email = request.Email
        };
        
        var result = await _userManager.CreateAsync(user, request.Password!);

        if (result.Succeeded)
        {
            request.Password = "";
            return CreatedAtAction(nameof(Register), new { email = request.Email }, request);
        }

        foreach (var error in result.Errors)
            ModelState.AddModelError(error.Code, error.Description);

        return BadRequest(ModelState);
    }

    [HttpPost]
    [Route("login")]
    public async Task<ActionResult<AuthResponse>> Authenticate([FromBody] AuthRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = await _userManager.FindByEmailAsync(request.Email!);
        if (user == null)
            return BadRequest("Bad credentials");

        var isPasswordValid = await _userManager.CheckPasswordAsync(user, request.Password!);
        if (!isPasswordValid)
            return BadRequest("Bad credentials");

        var accessToken = _tokenService.CreateAccessToken(user);
        var refreshToken = _tokenService.GenerateRefreshToken(user);

        return Ok(new AuthResponse
        {
            Username = user.UserName,
            Email = user.Email,
            Token = accessToken,
            RefreshToken = refreshToken,
            AccessTokenExpiryTime = DateTime.UtcNow.AddMinutes(TokenService.AccessTokenExpirationMinutes),
            ExpirationTokenExpiryTime = DateTime.UtcNow.AddDays(TokenService.RefreshTokenExpirationDays)
        });
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenModel tokenModel)
    {
        if (tokenModel == null)
            return BadRequest("Invalid client request");

        var (isValid, userId) = _tokenService.ValidateRefreshToken(tokenModel.RefreshToken);
        if (!isValid)
            return BadRequest("Invalid refresh token or token expired");

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return BadRequest("User not found");

        var newAccessToken = _tokenService.CreateAccessToken(user);
        var newRefreshToken = _tokenService.GenerateRefreshToken(user);

        return Ok(new
        {
            accessToken = newAccessToken,
            refreshToken = newRefreshToken
        });
    }
}

