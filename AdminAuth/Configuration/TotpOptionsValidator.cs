using Microsoft.Extensions.Options;

namespace AdminAuth.Configuration;

public sealed class TotpOptionsValidator : IValidateOptions<TotpOptions>
{
    public ValidateOptionsResult Validate(string? name, TotpOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            failures.Add("AdminAuth:TOTP:Issuer must be configured.");
        }

        if (options.PeriodSeconds is < 15 or > 120)
        {
            failures.Add("AdminAuth:TOTP:PeriodSeconds must be between 15 and 120.");
        }

        if (options.Digits is not (6 or 8))
        {
            failures.Add("AdminAuth:TOTP:Digits must be 6 or 8.");
        }

        if (options.AllowedClockSkewSteps is < 0 or > 2)
        {
            failures.Add("AdminAuth:TOTP:AllowedClockSkewSteps must be between 0 and 2.");
        }

        if (options.MaxFailedAttempts is < 3 or > 20)
        {
            failures.Add("AdminAuth:TOTP:MaxFailedAttempts must be between 3 and 20.");
        }

        if (options.LockoutDuration < TimeSpan.FromMinutes(1))
        {
            failures.Add("AdminAuth:TOTP:LockoutDuration must be at least one minute.");
        }

        if (options.RecoveryCodeCount is < 5 or > 20)
        {
            failures.Add("AdminAuth:TOTP:RecoveryCodeCount must be between 5 and 20.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
