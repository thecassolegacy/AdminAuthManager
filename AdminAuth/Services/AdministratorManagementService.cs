using System.Data;
using AdminAuth.Entities;
using AdminAuth.Persistence;
using Microsoft.EntityFrameworkCore;

namespace AdminAuth.Services;

public sealed class AdministratorManagementService(AdminAuthDbContext dbContext) : IAdministratorManagementService
{
    public Task GrantPermissionAsync(
        Guid actingAdministratorId,
        Guid targetAdministratorId,
        string permissionName,
        CancellationToken cancellationToken = default)
    {
        var name = PermissionNameRules.Validate(permissionName, nameof(permissionName));

        return RunAsync(async () =>
        {
            await RequireSuperAdminAsync(actingAdministratorId, cancellationToken);
            RejectSelfChange(actingAdministratorId, targetAdministratorId);

            var target = await FindTargetAsync(targetAdministratorId, cancellationToken);
            if (!target.IsActive)
            {
                throw new InvalidOperationException("Permissions cannot be granted to an inactive administrator.");
            }

            var permission = await FindPermissionAsync(name, cancellationToken);

            var alreadyGranted = await dbContext.AdminUserPermissions.AnyAsync(
                assignment => assignment.AdminUserId == target.Id && assignment.AdminPermissionId == permission.Id,
                cancellationToken);

            if (alreadyGranted)
            {
                return;
            }

            dbContext.AdminUserPermissions.Add(new AdminUserPermission
            {
                AdminUserId = target.Id,
                AdminPermissionId = permission.Id,
                GrantedByAdminUserId = actingAdministratorId
            });

            AddAudit(actingAdministratorId, target.Id, "PermissionGranted", permission.Name);
            await dbContext.SaveChangesAsync(cancellationToken);
        }, cancellationToken);
    }

    public Task RevokePermissionAsync(
        Guid actingAdministratorId,
        Guid targetAdministratorId,
        string permissionName,
        CancellationToken cancellationToken = default)
    {
        var name = PermissionNameRules.Validate(permissionName, nameof(permissionName));

        return RunAsync(async () =>
        {
            await RequireSuperAdminAsync(actingAdministratorId, cancellationToken);
            RejectSelfChange(actingAdministratorId, targetAdministratorId);

            var target = await FindTargetAsync(targetAdministratorId, cancellationToken);
            var permission = await FindPermissionAsync(name, cancellationToken);

            var assignment = await dbContext.AdminUserPermissions.SingleOrDefaultAsync(
                item => item.AdminUserId == target.Id && item.AdminPermissionId == permission.Id,
                cancellationToken);

            if (assignment is null)
            {
                return;
            }

            dbContext.AdminUserPermissions.Remove(assignment);
            AddAudit(actingAdministratorId, target.Id, "PermissionRevoked", permission.Name);
            await dbContext.SaveChangesAsync(cancellationToken);
        }, cancellationToken);
    }

    public Task PromoteAsync(
        Guid actingAdministratorId,
        Guid targetAdministratorId,
        CancellationToken cancellationToken = default)
    {
        return RunAsync(async () =>
        {
            await RequireSuperAdminAsync(actingAdministratorId, cancellationToken);
            RejectSelfChange(actingAdministratorId, targetAdministratorId);

            var target = await FindTargetAsync(targetAdministratorId, cancellationToken);
            if (!target.IsActive)
            {
                throw new InvalidOperationException("An inactive administrator cannot be promoted.");
            }

            if (target.IsSuperAdmin)
            {
                return;
            }

            target.IsSuperAdmin = true;
            AddAudit(actingAdministratorId, target.Id, "SuperAdminPromoted", null);
            await dbContext.SaveChangesAsync(cancellationToken);
        }, cancellationToken);
    }

    public Task DemoteAsync(
        Guid actingAdministratorId,
        Guid targetAdministratorId,
        CancellationToken cancellationToken = default)
    {
        return RunAsync(async () =>
        {
            await RequireSuperAdminAsync(actingAdministratorId, cancellationToken);

            var target = await FindTargetAsync(targetAdministratorId, cancellationToken);
            if (!target.IsSuperAdmin)
            {
                return;
            }

            if (target.IsActive)
            {
                var activeSuperAdmins = await dbContext.AdminUsers
                    .CountAsync(user => user.IsActive && user.IsSuperAdmin, cancellationToken);

                if (activeSuperAdmins <= 1)
                {
                    throw new InvalidOperationException("The last active super administrator cannot be demoted.");
                }
            }

            target.IsSuperAdmin = false;
            AddAudit(actingAdministratorId, target.Id, "SuperAdminDemoted", null);
            await dbContext.SaveChangesAsync(cancellationToken);
        }, cancellationToken);
    }

    private async Task RunAsync(Func<Task> operation, CancellationToken cancellationToken)
    {
        var strategy = dbContext.Database.CreateExecutionStrategy();

        await strategy.ExecuteAsync(async () =>
        {
            dbContext.ChangeTracker.Clear();

            await using var transaction = await dbContext.Database
                .BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

            await operation();
            await transaction.CommitAsync(cancellationToken);
        });
    }

    private async Task RequireSuperAdminAsync(Guid actingAdministratorId, CancellationToken cancellationToken)
    {
        var isSuperAdmin = await dbContext.AdminUsers.AnyAsync(
            user => user.Id == actingAdministratorId && user.IsActive && user.IsSuperAdmin,
            cancellationToken);

        if (!isSuperAdmin)
        {
            throw new UnauthorizedAccessException("Only active super administrators can perform this action.");
        }
    }

    private static void RejectSelfChange(Guid actingAdministratorId, Guid targetAdministratorId)
    {
        if (actingAdministratorId == targetAdministratorId)
        {
            throw new InvalidOperationException("Administrators cannot change their own permissions or super administrator status.");
        }
    }

    private async Task<AdminUser> FindTargetAsync(Guid targetAdministratorId, CancellationToken cancellationToken)
    {
        return await dbContext.AdminUsers.SingleOrDefaultAsync(user => user.Id == targetAdministratorId, cancellationToken)
            ?? throw new KeyNotFoundException("The administrator was not found.");
    }

    private async Task<AdminPermission> FindPermissionAsync(string name, CancellationToken cancellationToken)
    {
        var normalized = AdminAuthDbContext.NormalizeName(name);

        return await dbContext.AdminPermissions.SingleOrDefaultAsync(
                permission => permission.NormalizedName == normalized,
                cancellationToken)
            ?? throw new KeyNotFoundException("The permission was not found.");
    }

    private void AddAudit(Guid actingAdministratorId, Guid targetAdministratorId, string action, string? detail)
    {
        dbContext.AdminAuditEntries.Add(new AdminAuditEntry
        {
            ActorAdminUserId = actingAdministratorId,
            TargetAdminUserId = targetAdministratorId,
            Action = action,
            Detail = detail
        });
    }
}
