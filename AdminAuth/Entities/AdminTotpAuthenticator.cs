namespace AdminAuth.Entities;

public sealed class AdminTotpAuthenticator
{
    public Guid AdminUserId { get; set; }

    public AdminUser AdminUser { get; set; } = null!;

    public string ProtectedSecret { get; set; } = string.Empty;

    public bool IsEnabled { get; set; }

    public long? LastVerifiedTimeStep { get; set; }

    public int FailedAttemptCount { get; set; }

    public DateTimeOffset? LockoutEndUtc { get; set; }

    public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString("N");

    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? EnabledAtUtc { get; set; }
}
