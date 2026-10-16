using AdminAuth.Entities;

namespace AdminAuth.Persistence;

public interface IAdminUserStore
{
    /// <summary>
    /// Finds an API key by its public prefix, including its administrator and permissions.
    /// </summary>
    Task<AdminApiKey?> FindApiKeyByPrefixAsync(string prefix, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds an administrator by ID, including permissions, for revalidating token subjects.
    /// </summary>
    Task<AdminUser?> FindAdministratorAsync(Guid adminUserId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically counts
    /// </summary>
    Task RecordFailedAttemptAsync(
        Guid adminUserId,
        int maxAttempts,
        TimeSpan lockoutDuration,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Clears failure state and records last-used times, skipping writes newer than <paramref name="minInterval"/>.
    /// </summary>
    Task RecordSuccessAsync(
        Guid apiKeyId,
        Guid adminUserId,
        DateTimeOffset now,
        TimeSpan minInterval,
        CancellationToken cancellationToken = default);
}
