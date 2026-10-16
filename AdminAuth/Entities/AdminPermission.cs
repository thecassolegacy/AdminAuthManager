namespace AdminAuth.Entities;

public sealed class AdminPermission
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Name { get; set; } = string.Empty;

    public string NormalizedName { get; set; } = string.Empty;

    public string? Description { get; set; }

    public ICollection<AdminUserPermission> Users { get; set; } = new List<AdminUserPermission>();
}
