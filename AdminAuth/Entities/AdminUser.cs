namespace AdminAuth.Entities;

public sealed class AdminUser
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string UserName { get; set; } = string.Empty;

    public string NormalizedUserName { get; set; } = string.Empty;

    public bool IsActive { get; set; } = true;

    public bool IsSuperAdmin { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? LastAuthenticatedAtUtc { get; set; }

    public DateTimeOffset UpdatedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    public int FailedAccessCount { get; set; }

    public DateTimeOffset? LockoutEndUtc { get; set; }

    public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString("N");

    public ICollection<AdminApiKey> ApiKeys { get; set; } = new List<AdminApiKey>();

    public AdminTotpAuthenticator? TotpAuthenticator { get; set; }

    public ICollection<AdminUserPermission> Permissions { get; set; } = new List<AdminUserPermission>();
}
