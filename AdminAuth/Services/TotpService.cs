using System.Security.Cryptography;
using System.Text;
using AdminAuth.Configuration;
using AdminAuth.Entities;
using AdminAuth.Persistence;
using AdminAuth.Totp;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AdminAuth.Services;

public sealed class TotpService(
    AdminAuthDbContext dbContext,
    IDataProtectionProvider dataProtectionProvider,
    IOptions<TotpOptions> options,
    IOptions<AdminAuthOptions> adminAuthOptions,
    TimeProvider timeProvider) : ITotpService
{
    private const string RecoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private const int RecoveryCodeLength = 12;

    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector("AdminAuth.Totp.v1");

    public async Task<TotpEnrollment> BeginSetupAsync(
        Guid administratorId,
        string? currentCode = null,
        CancellationToken cancellationToken = default)
    {
        var administrator = await dbContext.AdminUsers
            .Include(user => user.TotpAuthenticator)
            .SingleOrDefaultAsync(user => user.Id == administratorId && user.IsActive, cancellationToken)
            ?? throw new InvalidOperationException("The administrator does not exist or is inactive.");

        var authenticator = administrator.TotpAuthenticator;

        if (authenticator is { IsEnabled: true })
        {
            if (string.IsNullOrWhiteSpace(currentCode)
                || !await VerifyCodeAsync(administratorId, currentCode, cancellationToken))
            {
                throw new UnauthorizedAccessException(
                    "A valid current code is required to replace an enabled authenticator.");
            }

            await dbContext.Entry(authenticator).ReloadAsync(cancellationToken);
        }

        var secret = Base32.Encode(RandomNumberGenerator.GetBytes(20));

        if (authenticator is null)
        {
            authenticator = new AdminTotpAuthenticator { AdminUserId = administrator.Id };
            dbContext.AdminTotpAuthenticators.Add(authenticator);
        }

        authenticator.ProtectedSecret = _protector.Protect(secret);
        authenticator.IsEnabled = false;
        authenticator.LastVerifiedTimeStep = null;
        authenticator.FailedAttemptCount = 0;
        authenticator.LockoutEndUtc = null;
        authenticator.CreatedAtUtc = timeProvider.GetUtcNow();
        authenticator.EnabledAtUtc = null;

        await dbContext.SaveChangesAsync(cancellationToken);

        return new TotpEnrollment(secret, BuildProvisioningUri(administrator.UserName, secret));
    }

    public async Task<TotpConfirmationResult> ConfirmSetupAsync(
        Guid administratorId,
        string code,
        CancellationToken cancellationToken = default)
    {
        if (!await VerifyCoreAsync(administratorId, code, confirming: true, cancellationToken))
        {
            return TotpConfirmationResult.Failed;
        }

        var authenticator = await dbContext.AdminTotpAuthenticators
            .SingleAsync(value => value.AdminUserId == administratorId, cancellationToken);

        var now = timeProvider.GetUtcNow();
        authenticator.IsEnabled = true;
        authenticator.EnabledAtUtc = now;

        await dbContext.AdminTotpRecoveryCodes
            .Where(recoveryCode => recoveryCode.AdminUserId == administratorId)
            .ExecuteDeleteAsync(cancellationToken);

        var plainCodes = new List<string>(options.Value.RecoveryCodeCount);
        for (var index = 0; index < options.Value.RecoveryCodeCount; index++)
        {
            var plainCode = GenerateRecoveryCode();
            plainCodes.Add(FormatRecoveryCode(plainCode));
            dbContext.AdminTotpRecoveryCodes.Add(new AdminTotpRecoveryCode
            {
                AdminUserId = administratorId,
                CodeHash = HashRecoveryCode(plainCode),
                CreatedAtUtc = now
            });
        }

        await dbContext.SaveChangesAsync(cancellationToken);

        return new TotpConfirmationResult(true, plainCodes);
    }

    public Task<bool> VerifyCodeAsync(
        Guid administratorId,
        string code,
        CancellationToken cancellationToken = default)
    {
        return VerifyCoreAsync(administratorId, code, confirming: false, cancellationToken);
    }

    public async Task<bool> VerifyRecoveryCodeAsync(
        Guid administratorId,
        string recoveryCode,
        CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();
        var authenticator = await dbContext.AdminTotpAuthenticators
            .AsNoTracking()
            .SingleOrDefaultAsync(
                value => value.AdminUserId == administratorId && value.AdminUser.IsActive,
                cancellationToken);

        if (authenticator is not { IsEnabled: true } || authenticator.LockoutEndUtc > now)
        {
            return false;
        }

        var normalized = NormalizeRecoveryCode(recoveryCode);
        var hash = normalized.Length == RecoveryCodeLength ? HashRecoveryCode(normalized) : string.Empty;

        var consumed = hash.Length == 0
            ? 0
            : await dbContext.AdminTotpRecoveryCodes
                .Where(value => value.AdminUserId == administratorId && value.CodeHash == hash && value.UsedAtUtc == null)
                .ExecuteUpdateAsync(setters => setters.SetProperty(value => value.UsedAtUtc, (DateTimeOffset?)now), cancellationToken);

        if (consumed != 1)
        {
            await RecordFailureAsync(administratorId, now, cancellationToken);
            return false;
        }

        await ClearFailuresAsync(administratorId, cancellationToken);
        return true;
    }

    public async Task<bool> DisableAsync(
        Guid administratorId,
        string codeOrRecoveryCode,
        CancellationToken cancellationToken = default)
    {
        var verified = await VerifyCodeAsync(administratorId, codeOrRecoveryCode, cancellationToken)
            || await VerifyRecoveryCodeAsync(administratorId, codeOrRecoveryCode, cancellationToken);

        if (!verified)
        {
            return false;
        }

        await RemoveFactorAsync(administratorId, cancellationToken);
        return true;
    }

    public async Task ResetAsync(
        Guid actingAdministratorId,
        Guid targetAdministratorId,
        CancellationToken cancellationToken = default)
    {
        if (actingAdministratorId == targetAdministratorId)
        {
            throw new InvalidOperationException(
                "Administrators cannot reset their own authenticator. Use DisableAsync with a valid code.");
        }

        var isSuperAdmin = await dbContext.AdminUsers
            .AsNoTracking()
            .AnyAsync(
                user => user.Id == actingAdministratorId && user.IsActive && user.IsSuperAdmin,
                cancellationToken);

        if (!isSuperAdmin)
        {
            throw new UnauthorizedAccessException("Only active super administrators can reset an authenticator.");
        }

        await RemoveFactorAsync(targetAdministratorId, cancellationToken);
    }

    private async Task RemoveFactorAsync(Guid administratorId, CancellationToken cancellationToken)
    {
        await dbContext.AdminTotpRecoveryCodes
            .Where(value => value.AdminUserId == administratorId)
            .ExecuteDeleteAsync(cancellationToken);

        await dbContext.AdminTotpAuthenticators
            .Where(value => value.AdminUserId == administratorId)
            .ExecuteDeleteAsync(cancellationToken);
    }

    private async Task<bool> VerifyCoreAsync(
        Guid administratorId,
        string code,
        bool confirming,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var authenticator = await dbContext.AdminTotpAuthenticators
            .AsNoTracking()
            .SingleOrDefaultAsync(
                value => value.AdminUserId == administratorId && value.AdminUser.IsActive,
                cancellationToken);

        if (authenticator is null || authenticator.IsEnabled == confirming || authenticator.LockoutEndUtc > now)
        {
            return false;
        }

        if (!TryGetMatchingTimeStep(authenticator.ProtectedSecret, code, now, out var timeStep))
        {
            await RecordFailureAsync(administratorId, now, cancellationToken);
            return false;
        }

        // Atomic replay guard: only one concurrent request can advance the time step.
        var advanced = await dbContext.AdminTotpAuthenticators
            .Where(value => value.AdminUserId == administratorId
                && (value.LastVerifiedTimeStep == null || value.LastVerifiedTimeStep < timeStep))
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(value => value.LastVerifiedTimeStep, (long?)timeStep)
                    .SetProperty(value => value.FailedAttemptCount, 0)
                    .SetProperty(value => value.LockoutEndUtc, (DateTimeOffset?)null),
                cancellationToken);

        return advanced == 1;
    }

    private async Task RecordFailureAsync(Guid administratorId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var maxAttempts = options.Value.MaxFailedAttempts;
        var lockoutEnd = now.Add(options.Value.LockoutDuration);

        await dbContext.AdminTotpAuthenticators
            .Where(value => value.AdminUserId == administratorId)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(value => value.FailedAttemptCount, value => value.FailedAttemptCount + 1),
                cancellationToken);

        await dbContext.AdminTotpAuthenticators
            .Where(value => value.AdminUserId == administratorId && value.FailedAttemptCount >= maxAttempts)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(value => value.LockoutEndUtc, (DateTimeOffset?)lockoutEnd)
                    .SetProperty(value => value.FailedAttemptCount, 0),
                cancellationToken);
    }

    private Task ClearFailuresAsync(Guid administratorId, CancellationToken cancellationToken)
    {
        return dbContext.AdminTotpAuthenticators
            .Where(value => value.AdminUserId == administratorId)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(value => value.FailedAttemptCount, 0)
                    .SetProperty(value => value.LockoutEndUtc, (DateTimeOffset?)null),
                cancellationToken);
    }

    /// <summary>
    /// Accepts the current time step and up to <see cref="TotpOptions.AllowedClockSkewSteps"/> earlier steps.
    /// Future steps are rejected so a code can never advance the replay marker past the present.
    /// </summary>
    private bool TryGetMatchingTimeStep(string protectedSecret, string code, DateTimeOffset now, out long timeStep)
    {
        timeStep = default;

        if (string.IsNullOrWhiteSpace(code))
        {
            return false;
        }

        byte[] secret;
        try
        {
            secret = Base32.Decode(_protector.Unprotect(protectedSecret));
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }

        var trimmed = code.Trim();
        var currentTimeStep = now.ToUnixTimeSeconds() / options.Value.PeriodSeconds;
        var found = false;

        // Evaluate every window so timing does not reveal which step matched.
        for (var offset = 0; offset <= options.Value.AllowedClockSkewSteps; offset++)
        {
            var candidate = currentTimeStep - offset;
            var expected = TotpCodeGenerator.GenerateCode(secret, candidate, options.Value.Digits);

            if (TotpCodeGenerator.Matches(expected, trimmed) && (!found || candidate > timeStep))
            {
                timeStep = candidate;
                found = true;
            }
        }

        return found;
    }

    private static string GenerateRecoveryCode()
    {
        var bytes = RandomNumberGenerator.GetBytes(RecoveryCodeLength);
        var characters = new char[RecoveryCodeLength];

        for (var index = 0; index < characters.Length; index++)
        {
            characters[index] = RecoveryAlphabet[bytes[index] & 31];
        }

        return new string(characters);
    }

    private static string FormatRecoveryCode(string code) => $"{code[..4]}-{code[4..8]}-{code[8..]}";

    private static string NormalizeRecoveryCode(string code)
    {
        return new string(code.Where(character => character != '-' && !char.IsWhiteSpace(character)).ToArray())
            .ToUpperInvariant();
    }

    private string HashRecoveryCode(string normalizedCode)
    {
        var pepper = Encoding.UTF8.GetBytes(adminAuthOptions.Value.ApiKeyPepper);
        return Convert.ToHexString(HMACSHA256.HashData(pepper, Encoding.UTF8.GetBytes(normalizedCode)));
    }

    private string BuildProvisioningUri(string userName, string secret)
    {
        var issuer = options.Value.Issuer;
        var label = Uri.EscapeDataString($"{issuer}:{userName}");

        return $"otpauth://totp/{label}?secret={Uri.EscapeDataString(secret)}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits={options.Value.Digits}&period={options.Value.PeriodSeconds}";
    }
}
