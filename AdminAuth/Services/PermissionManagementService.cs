using AdminAuth.Entities;
using AdminAuth.Persistence;
using Microsoft.EntityFrameworkCore;

namespace AdminAuth.Services;

public sealed class PermissionManagementService(AdminAuthDbContext dbContext) : IPermissionManagementService
{
    public async Task<AdminPermission> CreatePermissionAsync(
        Guid actingAdministratorId,
        string name,
        string? description = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var normalizedName = PermissionNameRules.Validate(name);
        var normalizedDescription = string.IsNullOrWhiteSpace(description) ? null : description.Trim();

        if (normalizedDescription?.Length > 1_024)
        {
            throw new ArgumentException("Permission descriptions cannot exceed 1024 characters.", nameof(description));
        }

        var isSuperAdmin = await dbContext.AdminUsers
            .AsNoTracking()
            .AnyAsync(
                user => user.Id == actingAdministratorId && user.IsActive && user.IsSuperAdmin,
                cancellationToken);

        if (!isSuperAdmin)
        {
            throw new UnauthorizedAccessException("Only active super administrators can create permissions.");
        }

        var normalizedKey = AdminAuthDbContext.NormalizeName(normalizedName);
        var exists = await dbContext.AdminPermissions
            .AnyAsync(permission => permission.NormalizedName == normalizedKey, cancellationToken);

        if (exists)
        {
            throw new InvalidOperationException($"The permission '{normalizedName}' already exists.");
        }

        var permission = new AdminPermission
        {
            Name = normalizedName,
            Description = normalizedDescription
        };

        dbContext.AdminPermissions.Add(permission);

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            dbContext.Entry(permission).State = EntityState.Detached;

            if (await dbContext.AdminPermissions.AnyAsync(
                    existing => existing.NormalizedName == normalizedKey,
                    cancellationToken))
            {
                throw new InvalidOperationException($"The permission '{normalizedName}' already exists.");
            }

            throw;
        }

        return permission;
    }
}
