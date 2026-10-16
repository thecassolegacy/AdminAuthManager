using AdminAuth.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace AdminAuth.Extensions;

public static class AdminAuthEndpointRouteBuilderExtensions
{
    public sealed record AdminTokenRequest(string? ApiKey, string? TotpCode);

    /// <summary>
    /// Maps an anonymous POST endpoint that exchanges an API key (plus TOTP code when enrolled) for a JWT.
    /// The API key is read from the JSON body, not the header, so the API-key scheme cannot double-count failures.
    /// Protect it with rate limiting.
    /// </summary>
    public static RouteHandlerBuilder MapAdminTokenEndpoint(
        this IEndpointRouteBuilder endpoints,
        string pattern = "/admin/auth/token")
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        return endpoints.MapPost(pattern, async (
            AdminTokenRequest request,
            IAdminTokenService tokenService,
            CancellationToken cancellationToken) =>
        {
            var result = await tokenService.IssueTokenAsync(
                request.ApiKey ?? string.Empty, request.TotpCode, cancellationToken);

            if (result.Succeeded)
            {
                return Results.Ok(new
                {
                    access_token = result.Token,
                    token_type = "Bearer",
                    expires_at = result.ExpiresAtUtc,
                    mfa = result.MfaSatisfied
                });
            }

            return Results.Json(
                new { error = result.MfaRequired ? "mfa_required" : "invalid_credentials" },
                statusCode: StatusCodes.Status401Unauthorized);
        }).AllowAnonymous();
    }
}
