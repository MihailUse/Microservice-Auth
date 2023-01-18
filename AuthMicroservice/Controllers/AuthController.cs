using AuthMicroservice.DAL.Entities;
using AuthMicroservice.Models;
using AuthMicroservice.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthMicroservice.Controllers;

/// <summary>
/// Main auth controller
/// </summary>
[Route("api/[controller]/[action]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly AuthService _authService;
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="userManager"></param>
    /// <param name="signInManager"></param>
    public AuthController(AuthService authService, UserManager<User> userManager, SignInManager<User> signInManager)
    {
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
        {
            var token = _authService.GenerateTokens(user);
            return Ok(token);
        }

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
}
