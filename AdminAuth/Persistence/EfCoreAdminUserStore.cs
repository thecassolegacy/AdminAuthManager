using AdminAuth.Entities;
using Microsoft.EntityFrameworkCore;

namespace AdminAuth.Persistence;

public sealed class EfCoreAdminUserStore(AdminAuthDbContext dbContext) : IAdminUserStore
{
    public Task<AdminApiKey?> FindApiKeyByPrefixAsync(string prefix, CancellationToken cancellationToken = default)
    {
        return dbContext.AdminApiKeys
            .AsNoTracking()
            .Include(key => key.AdminUser)
                .ThenInclude(user => user.Permissions)
                    .ThenInclude(permission => permission.AdminPermission)
            .SingleOrDefaultAsync(key => key.Prefix == prefix, cancellationToken);
    }

    public Task<AdminUser?> FindAdministratorAsync(Guid adminUserId, CancellationToken cancellationToken = default)
    {
        return dbContext.AdminUsers
            .AsNoTracking()
            .Include(user => user.Permissions)
                .ThenInclude(permission => permission.AdminPermission)
            .SingleOrDefaultAsync(user => user.Id == adminUserId, cancellationToken);
    }

    public async Task RecordFailedAttemptAsync(
        Guid adminUserId,
        int maxAttempts,
        TimeSpan lockoutDuration,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        await dbContext.AdminUsers
            .Where(user => user.Id == adminUserId)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(user => user.FailedAccessCount, user => user.FailedAccessCount + 1),
                cancellationToken);

        var lockoutEnd = now.Add(lockoutDuration);

        await dbContext.AdminUsers
            .Where(user => user.Id == adminUserId && user.FailedAccessCount >= maxAttempts)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(user => user.LockoutEndUtc, lockoutEnd)
                    .SetProperty(user => user.FailedAccessCount, 0),
                cancellationToken);
    }

    public async Task RecordSuccessAsync(
        Guid apiKeyId,
        Guid adminUserId,
        DateTimeOffset now,
        TimeSpan minInterval,
        CancellationToken cancellationToken = default)
    {
        var threshold = now.Subtract(minInterval);

        await dbContext.AdminApiKeys
            .Where(key => key.Id == apiKeyId && (key.LastUsedAtUtc == null || key.LastUsedAtUtc < threshold))
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(key => key.LastUsedAtUtc, now),
                cancellationToken);

        await dbContext.AdminUsers
            .Where(user => user.Id == adminUserId
                && (user.FailedAccessCount > 0
                    || user.LockoutEndUtc != null
                    || user.LastAuthenticatedAtUtc == null
                    || user.LastAuthenticatedAtUtc < threshold))
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(user => user.FailedAccessCount, 0)
                    .SetProperty(user => user.LockoutEndUtc, (DateTimeOffset?)null)
                    .SetProperty(user => user.LastAuthenticatedAtUtc, now),
                cancellationToken);
    }
}
