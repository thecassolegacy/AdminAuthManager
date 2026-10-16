namespace AdminAuth.Authentication;

/// <summary>
/// Exchanges an administrator's API key (and TOTP code when a factor is enabled) for a short-lived JWT.
/// </summary>
public interface IAdminTokenService
{
    /// <summary>
    /// Returns <see cref="AdminTokenResult.Failed"/> for any invalid credential, and
    /// <see cref="AdminTokenResult.RequiresMfa"/> when the key is valid but a TOTP or recovery code is needed.
    /// Applies the same lockout rules as API-key authentication. The token carries the <c>admin_mfa</c> claim
    /// only when a TOTP or recovery code was verified.
    /// </summary>
    Task<AdminTokenResult> IssueTokenAsync(
        string apiKey,
        string? totpCode = null,
        CancellationToken cancellationToken = default);
}
