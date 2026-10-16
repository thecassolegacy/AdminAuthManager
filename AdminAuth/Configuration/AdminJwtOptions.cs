namespace AdminAuth.Configuration;

/// <summary>
/// Settings for issuing and validating the JWTs produced by <c>IAdminTokenService</c>.
/// </summary>
public sealed class AdminJwtOptions
{
    public string Issuer { get; set; } = string.Empty;

    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// HMAC-SHA256 signing secret, at least 32 bytes (UTF-8). Keep it in a secret store.
    /// When set, the JWT bearer scheme is configured from these values automatically.
    /// </summary>
    public string SigningKey { get; set; } = string.Empty;

    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromMinutes(15);
}
