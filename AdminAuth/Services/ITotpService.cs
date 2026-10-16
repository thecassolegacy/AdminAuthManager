namespace AdminAuth.Services;

public interface ITotpService
{
    /// <summary>
    /// Starts enrollment. When an authenticator is already enabled, a valid current code is required to replace it.
    /// </summary>
    Task<TotpEnrollment> BeginSetupAsync(
        Guid administratorId,
        string? currentCode = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Confirms enrollment with the first code. On success the factor is enabled and one-time recovery codes are returned once.
    /// </summary>
    Task<TotpConfirmationResult> ConfirmSetupAsync(
        Guid administratorId,
        string code,
        CancellationToken cancellationToken = default);

    Task<bool> VerifyCodeAsync(Guid administratorId, string code, CancellationToken cancellationToken = default);

    Task<bool> VerifyRecoveryCodeAsync(Guid administratorId, string recoveryCode, CancellationToken cancellationToken = default);

    /// <summary>
    /// Self-service removal. Requires a valid TOTP code or an unused recovery code.
    /// </summary>
    Task<bool> DisableAsync(Guid administratorId, string codeOrRecoveryCode, CancellationToken cancellationToken = default);

    /// <summary>
    /// Administrative reset for a lost device. The acting administrator must be an active super administrator and cannot be the target.
    /// </summary>
    Task ResetAsync(Guid actingAdministratorId, Guid targetAdministratorId, CancellationToken cancellationToken = default);
}
