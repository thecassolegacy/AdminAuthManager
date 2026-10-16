namespace AdminAuth.Entities;

/// <summary>
/// Append-only record of a security-relevant administrative action.
/// </summary>
public class AdminAuditEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public DateTimeOffset OccurredAtUtc { get; set; } = DateTimeOffset.UtcNow;

    public Guid ActorAdminUserId { get; set; }

    public Guid? TargetAdminUserId { get; set; }

    public string Action { get; set; } = string.Empty;

    public string? Detail { get; set; }
}
