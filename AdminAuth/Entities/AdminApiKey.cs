namespace AdminAuth.Entities;

public sealed class AdminApiKey
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid AdminUserId { get; set; }

    public AdminUser AdminUser { get; set; } = null!;

    public string Prefix { get; set; } = string.Empty;

    public string KeyHash { get; set; } = string.Empty;

    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? ExpiresAtUtc { get; set; }

    public DateTimeOffset? RevokedAtUtc { get; set; }

    public DateTimeOffset? LastUsedAtUtc { get; set; }
}
