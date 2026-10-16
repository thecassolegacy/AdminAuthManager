namespace AdminAuth.Authentication;

public sealed record AdminTokenResult(bool Succeeded, bool MfaRequired, string? Token, DateTimeOffset? ExpiresAtUtc, bool MfaSatisfied)
{
    public static AdminTokenResult Failed { get; } = new(false, false, null, null, false);

    public static AdminTokenResult RequiresMfa { get; } = new(false, true, null, null, false);
}
