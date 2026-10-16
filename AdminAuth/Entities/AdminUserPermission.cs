namespace AdminAuth.Entities;

public sealed class AdminUserPermission
{
    public Guid AdminUserId { get; set; }

    public AdminUser AdminUser { get; set; } = null!;

    public Guid AdminPermissionId { get; set; }

    public AdminPermission AdminPermission { get; set; } = null!;

    public DateTimeOffset GrantedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    public Guid? GrantedByAdminUserId { get; set; }
}
