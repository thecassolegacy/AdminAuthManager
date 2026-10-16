namespace AdminAuth.Services;

public sealed record TotpConfirmationResult(bool Succeeded, IReadOnlyList<string> RecoveryCodes)
{
    public static TotpConfirmationResult Failed { get; } = new(false, Array.Empty<string>());
}
