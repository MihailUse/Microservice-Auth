using AuthMicroservice.Configs;
using AuthMicroservice.DAL.Entities;
using AuthMicroservice.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace AuthMicroservice.Services;

public class AuthService
{
    private readonly AuthConfig _authConfig;

    public AuthService(IOptions<AuthConfig> authConfig)
    {
        _authConfig = authConfig.Value;
    }

    public TokenModel GenerateTokens(User user)
    {
        Claim[] tokenClaims = new Claim[]
        {
                new Claim(JwtRegisteredClaimNames.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, user.Id.ToString()),
        };

        return new TokenModel()
        {
            AccessToken = GenerateEncodedToken(tokenClaims, _authConfig.LifeTime)
        };
    }

    private string GenerateEncodedToken(Claim[] claims, int lifeTime)
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
