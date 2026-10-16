using AdminAuth.Entities;

namespace AdminAuth.Services;

public interface IPermissionManagementService
{
    Task<AdminPermission> CreatePermissionAsync(
        Guid actingAdministratorId,
        string name,
        string? description = null,
        CancellationToken cancellationToken = default);
}
