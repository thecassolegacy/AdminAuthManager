namespace AdminAuth.Services;

/// <summary>
/// Guarded administrator changes. Every operation requires an active super administrator, runs in a
/// serializable transaction and writes an audit entry. Failures throw <see cref="UnauthorizedAccessException"/>,
/// <see cref="KeyNotFoundException"/>, <see cref="InvalidOperationException"/> or <see cref="ArgumentException"/>.
/// </summary>
public interface IAdministratorManagementService
{
    /// <summary>Grants a permission. Administrators cannot change their own permissions.</summary>
    Task GrantPermissionAsync(
        Guid actingAdministratorId,
        Guid targetAdministratorId,
        string permissionName,
        CancellationToken cancellationToken = default);

    /// <summary>Revokes a permission. Administrators cannot change their own permissions.</summary>
    Task RevokePermissionAsync(
        Guid actingAdministratorId,
        Guid targetAdministratorId,
        string permissionName,
        CancellationToken cancellationToken = default);

    /// <summary>Makes another active administrator a super administrator.</summary>
    Task PromoteAsync(
        Guid actingAdministratorId,
        Guid targetAdministratorId,
        CancellationToken cancellationToken = default);

    /// <summary>Removes super administrator status. The last active super administrator cannot be demoted.</summary>
    Task DemoteAsync(
        Guid actingAdministratorId,
        Guid targetAdministratorId,
        CancellationToken cancellationToken = default);
}
