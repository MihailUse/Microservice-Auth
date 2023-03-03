using System.IdentityModel.Tokens.Jwt;
using AuthMicroservice.Configs;
using AuthMicroservice.DAL.Entities;
using AuthMicroservice.Models;
using AuthMicroservice.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthMicroservice.Controllers;

/// <summary>
/// Main auth controller
/// </summary>
[Route("api/[controller]/[action]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly AuthConfig _authConfig;
    private readonly AuthService _authService;
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authConfig"></param>
    /// <param name="authService"></param>
    /// <param name="userManager"></param>
    /// <param name="signInManager"></param>
    public AuthController(IOptions<AuthConfig> authConfig, AuthService authService, UserManager<User> userManager, SignInManager<User> signInManager)
    {
        _authConfig = authConfig.Value;
        _authService = authService;
        _userManager = userManager;
        _signInManager = signInManager;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="signInModel"></param>
    /// <response code="200">The response with JWT</response>
    /// <response code="401">Invalid credentials</response>
    /// <response code="404">User not found</response>
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(TokenModel))]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> SignIn(SignInModel signInModel)
    {
        var user = await _userManager.FindByEmailAsync(signInModel.Email);
        if (user == null)
            return NotFound();

        var result = await _signInManager.CheckPasswordSignInAsync(user, signInModel.Password, false);
        if (result.Succeeded)
            return Ok(_authService.GenerateTokens(user));

        return Unauthorized();
    }

    /// <summary>
    /// Register new user
    /// </summary>
    /// <param name="signUpModel"></param>
    /// <response code="200">The response with JWT</response>
    /// <response code="400">The response with error info</response>
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(TokenModel))]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> SignUp(SignUpModel signUpModel)
    {
        var user = new User()
        {
            UserName = signUpModel.Login,
            Email = signUpModel.Email,
        };

        var result = await _userManager.CreateAsync(user, signUpModel.Password);
        if (result.Succeeded)
        {
            var token = _authService.GenerateTokens(user);
            return Ok(token);
        }

        foreach (var error in result.Errors)
            ModelState.AddModelError(error.Code, error.Description);

        return BadRequest(ModelState);
    }
    
    /// <summary>
    /// 
    /// </summary>
    /// <param name="refreshToken"></param>
    /// <returns></returns>
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(TokenModel))]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Refresh([FromBody] string refreshToken)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _authConfig.SymmetricSecurityKey(),
            ValidateLifetime = true
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(refreshToken, tokenValidationParameters, out SecurityToken securityToken);
        if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            return Unauthorized("Invalid token");

        var userId = principal.Claims.FirstOrDefault(x => x.Type == "UserId")?.Value;
        var user = await _userManager.Users.FirstOrDefaultAsync(x => x.Id == userId);
        if (user == null)
            return Unauthorized("User not found");

        return Ok(_authService.GenerateTokens(user));
    }
}
