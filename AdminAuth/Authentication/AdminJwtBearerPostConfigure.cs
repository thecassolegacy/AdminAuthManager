using AdminAuth.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace AdminAuth.Authentication;

/// <summary>
/// Applies <see cref="AdminJwtOptions"/> to the JWT bearer scheme so tokens issued by the library are
/// validated strictly, without consumers repeating the settings.
/// </summary>
public sealed class AdminJwtBearerPostConfigure(IOptions<AdminAuthOptions> adminAuthOptions)
    : IPostConfigureOptions<JwtBearerOptions>
{
    public void PostConfigure(string? name, JwtBearerOptions options)
    {
        if (name != JwtBearerDefaults.AuthenticationScheme)
        {
            return;
        }

        var jwt = adminAuthOptions.Value.Jwt;

        if (string.IsNullOrWhiteSpace(jwt.SigningKey))
        {
            return;
        }

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwt.Issuer,
            ValidateAudience = true,
            ValidAudience = jwt.Audience,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            ClockSkew = TimeSpan.FromMinutes(1),
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey))
        };
    }
}
