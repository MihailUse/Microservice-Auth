using AuthMicroservice.Configs;
using AuthMicroservice.DAL.Entities;
using AuthMicroservice.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace AuthMicroservice.Services;

/// <summary>
/// 
/// </summary>
public class AuthService
{
    private readonly AuthConfig _authConfig;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authConfig"></param>
    public AuthService(IOptions<AuthConfig> authConfig)
    {
        _authConfig = authConfig.Value;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    public TokenModel GenerateTokens(User user)
    {
        Claim[] tokenClaims = new Claim[]
        {
            new Claim("UserId", user.Id),
        };
        
        Claim[] refreshTokenClaims = new Claim[]
        {
            new Claim("UserId", user.Id),
        };

        return new TokenModel()
        {
            AccessToken = GenerateEncodedToken(tokenClaims, _authConfig.LifeTime),
            RefreshToken = GenerateEncodedToken(refreshTokenClaims, _authConfig.RefreshLifeTime)
        };
    }

    private string GenerateEncodedToken(IEnumerable<Claim> claims, int lifeTime)
    {
        var dateTime = DateTime.UtcNow;
        var token = new JwtSecurityToken(
            issuer: _authConfig.Issuer,
            audience: _authConfig.Audience,
            claims: claims,
            notBefore: dateTime,
            expires: dateTime.AddMinutes(lifeTime),
            signingCredentials: new SigningCredentials(_authConfig.SymmetricSecurityKey(), SecurityAlgorithms.HmacSha256)
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
