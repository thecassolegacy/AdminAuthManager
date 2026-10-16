using System.Security.Claims;
using System.Text;
using AdminAuth.Authorization;
using AdminAuth.Configuration;
using AdminAuth.Persistence;
using AdminAuth.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AdminAuth.Authentication;

public sealed class AdminTokenService(
    IAdminUserStore userStore,
    IApiKeyService apiKeyService,
    ITotpService totpService,
    AdminAuthDbContext dbContext,
    IOptions<AdminAuthOptions> options,
    TimeProvider timeProvider,
    ILogger<AdminTokenService> logger) : IAdminTokenService
{
    public async Task<AdminTokenResult> IssueTokenAsync(
        string apiKey,
        string? totpCode = null,
        CancellationToken cancellationToken = default)
    {
        var settings = options.Value;
        var jwt = settings.Jwt;

        if (string.IsNullOrWhiteSpace(jwt.SigningKey))
        {
            throw new InvalidOperationException("AdminAuthOptions.Jwt.SigningKey must be configured to issue tokens.");
        }

        if (string.IsNullOrWhiteSpace(apiKey) || !apiKeyService.TryParse(apiKey, out var prefix, out var secret))
        {
            return AdminTokenResult.Failed;
        }

        var storedKey = await userStore.FindApiKeyByPrefixAsync(prefix, cancellationToken);
        var now = timeProvider.GetUtcNow();

        var secretMatches = apiKeyService.Verify(secret, storedKey?.KeyHash ?? new string('0', 64));

        if (storedKey is null)
        {
            logger.LogWarning("Admin token request rejected: unknown key.");
            return AdminTokenResult.Failed;
        }

        var user = storedKey.AdminUser;

        if (user.LockoutEndUtc is not null && user.LockoutEndUtc > now)
        {
            logger.LogWarning("Admin token request rejected: administrator {AdminUserId} is locked out.", user.Id);
            return AdminTokenResult.Failed;
        }

        if (!secretMatches)
        {
            await userStore.RecordFailedAttemptAsync(
                user.Id, settings.MaxFailedAccessAttempts, settings.LockoutDuration, now, cancellationToken);
            logger.LogWarning("Admin token request rejected: wrong secret for administrator {AdminUserId}.", user.Id);
            return AdminTokenResult.Failed;
        }

        if (storedKey.RevokedAtUtc is not null
            || (storedKey.ExpiresAtUtc is not null && storedKey.ExpiresAtUtc <= now)
            || !user.IsActive)
        {
            logger.LogWarning("Admin token request rejected: key {ApiKeyId} unusable.", storedKey.Id);
            return AdminTokenResult.Failed;
        }

        var hasTotp = await dbContext.AdminTotpAuthenticators
            .AsNoTracking()
            .AnyAsync(factor => factor.AdminUserId == user.Id && factor.IsEnabled, cancellationToken);

        var mfaSatisfied = false;

        if (hasTotp)
        {
            if (string.IsNullOrWhiteSpace(totpCode))
            {
                return AdminTokenResult.RequiresMfa;
            }

            var code = totpCode.Trim();
            var isTotpCode = code.Length <= 8 && code.All(char.IsAsciiDigit);

            mfaSatisfied = isTotpCode
                ? await totpService.VerifyCodeAsync(user.Id, code, cancellationToken)
                : await totpService.VerifyRecoveryCodeAsync(user.Id, code, cancellationToken);

            if (!mfaSatisfied)
            {
                logger.LogWarning("Admin token request rejected: invalid second factor for administrator {AdminUserId}.", user.Id);
                return AdminTokenResult.Failed;
            }
        }

        await userStore.RecordSuccessAsync(storedKey.Id, user.Id, now, settings.LastUsedUpdateInterval, cancellationToken);

        var expires = now.Add(jwt.TokenLifetime);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Name, user.UserName),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
        };

        if (mfaSatisfied)
        {
            claims.Add(new Claim(AdminAuthClaimTypes.Mfa, bool.TrueString));
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = jwt.Issuer,
            Audience = jwt.Audience,
            Subject = new ClaimsIdentity(claims),
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey)),
                SecurityAlgorithms.HmacSha256)
        };

        var token = new JsonWebTokenHandler().CreateToken(descriptor);

        return new AdminTokenResult(true, false, token, expires, mfaSatisfied);
    }
}
