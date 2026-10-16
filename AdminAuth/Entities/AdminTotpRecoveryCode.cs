namespace AdminAuth.Entities;

public sealed class AdminTotpRecoveryCode
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid AdminUserId { get; set; }

    public string CodeHash { get; set; } = string.Empty;

    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? UsedAtUtc { get; set; }
}
