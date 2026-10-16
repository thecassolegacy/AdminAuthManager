using System.Security.Claims;
using System.Text.Encodings.Web;
using AdminAuth.Authorization;
using AdminAuth.Configuration;
using AdminAuth.Persistence;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AdminAuth.Authentication;

public sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IAdminUserStore userStore,
    IApiKeyService apiKeyService,
    IOptions<AdminAuthOptions> adminAuthOptions)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    private const string InvalidKeyMessage = "The API key is invalid.";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var settings = adminAuthOptions.Value;

        if (!Request.Headers.TryGetValue(settings.ApiKeyHeaderName, out var values))
        {
            return AuthenticateResult.NoResult();
        }

        if (values.Count != 1 || string.IsNullOrWhiteSpace(values[0]))
        {
            Logger.LogWarning("Admin API key rejected: malformed header from {RemoteIp}.", RemoteIp);
            return AuthenticateResult.Fail(InvalidKeyMessage);
        }

        if (!apiKeyService.TryParse(values[0]!, out var prefix, out var secret))
        {
            Logger.LogWarning("Admin API key rejected: malformed key from {RemoteIp}.", RemoteIp);
            return AuthenticateResult.Fail(InvalidKeyMessage);
        }

        var apiKey = await userStore.FindApiKeyByPrefixAsync(prefix, Context.RequestAborted);
        var now = TimeProvider.GetUtcNow();

        // Always compute the hash so unknown prefixes cost the same as known ones.
        var secretMatches = apiKeyService.Verify(secret, apiKey?.KeyHash ?? new string('0', 64));

        if (apiKey is null)
        {
            Logger.LogWarning("Admin API key rejected: unknown key from {RemoteIp}.", RemoteIp);
            return AuthenticateResult.Fail(InvalidKeyMessage);
        }

        var user = apiKey.AdminUser;

        if (user.LockoutEndUtc is not null && user.LockoutEndUtc > now)
        {
            Logger.LogWarning(
                "Admin API key rejected: administrator {AdminUserId} is locked out until {LockoutEnd} (request from {RemoteIp}).",
                user.Id, user.LockoutEndUtc, RemoteIp);
            return AuthenticateResult.Fail(InvalidKeyMessage);
        }

        if (!secretMatches)
        {
            await userStore.RecordFailedAttemptAsync(
                user.Id,
                settings.MaxFailedAccessAttempts,
                settings.LockoutDuration,
                now,
                Context.RequestAborted);

            Logger.LogWarning(
                "Admin API key rejected: wrong secret for administrator {AdminUserId} from {RemoteIp}.",
                user.Id, RemoteIp);
            return AuthenticateResult.Fail(InvalidKeyMessage);
        }

        if (apiKey.RevokedAtUtc is not null
            || (apiKey.ExpiresAtUtc is not null && apiKey.ExpiresAtUtc <= now)
            || !user.IsActive)
        {
            Logger.LogWarning(
                "Admin API key rejected: key {ApiKeyId} is revoked, expired, or the administrator {AdminUserId} is inactive.",
                apiKey.Id, user.Id);
            return AuthenticateResult.Fail(InvalidKeyMessage);
        }

        await userStore.RecordSuccessAsync(
            apiKey.Id,
            user.Id,
            now,
            settings.LastUsedUpdateInterval,
            Context.RequestAborted);

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.UserName)
        };

        if (user.IsSuperAdmin)
        {
            claims.Add(new Claim(AdminAuthClaimTypes.SuperAdmin, bool.TrueString));
        }

        claims.AddRange(user.Permissions.Select(permission =>
            new Claim(AdminAuthClaimTypes.Permission, permission.AdminPermission.Name)));

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);

        return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
    }

    private string? RemoteIp => Context.Connection.RemoteIpAddress?.ToString();
}
