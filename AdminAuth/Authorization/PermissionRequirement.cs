using Microsoft.AspNetCore.Authorization;

namespace AdminAuth.Authorization;

public sealed class PermissionRequirement(string permission) : IAuthorizationRequirement
{
    public string Permission { get; } = !string.IsNullOrWhiteSpace(permission)
        ? permission
        : throw new ArgumentException("A permission name is required.", nameof(permission));
}
