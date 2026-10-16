namespace AdminAuth.Configuration;

public sealed class AdminAuthOptions
{
    public string ApiKeyHeaderName { get; set; } = "X-Api-Key";

    /// <summary>
    /// Server-side secret mixed into API key hashes. Must be at least 32 characters and kept outside the database.
    /// </summary>
    public string ApiKeyPepper { get; set; } = string.Empty;

    /// <summary>
    /// Application name used to isolate Data Protection (TOTP secret) keys. Set it identically on every instance.
    /// </summary>
    public string DataProtectionApplicationName { get; set; } = "AdminAuth";

    /// <summary>
    /// Allows JwtBearerOptions.RequireHttpsMetadata = false. Intended for local development only.
    /// </summary>
    public bool AllowInsecureJwtMetadata { get; set; }

    /// <summary>
    /// When true, <c>AdminAuth</c> becomes the application's default authenticate/challenge scheme.
    /// When false, the consumer's defaults are kept and policies created by the helpers still use AdminAuth.
    /// </summary>
    public bool SetAsDefaultScheme { get; set; }

    public int MaxFailedAccessAttempts { get; set; } = 5;

    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);

    public TimeSpan LastUsedUpdateInterval { get; set; } = TimeSpan.FromMinutes(5);
}
