using Microsoft.Extensions.Options;

namespace AdminAuth.Configuration;

public sealed class AdminAuthOptionsValidator : IValidateOptions<AdminAuthOptions>
{
    public ValidateOptionsResult Validate(string? name, AdminAuthOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.ApiKeyHeaderName))
        {
            return ValidateOptionsResult.Fail("AdminAuth:ApiKeyHeaderName must be configured.");
        }

        if (options.MaxFailedAccessAttempts is < 3 or > 100)
        {
            return ValidateOptionsResult.Fail("AdminAuth:MaxFailedAccessAttempts must be between 3 and 100.");
        }

        if (options.LockoutDuration < TimeSpan.FromMinutes(1))
        {
            return ValidateOptionsResult.Fail("AdminAuth:LockoutDuration must be at least one minute.");
        }

        return options.ApiKeyPepper is { Length: >= 32 }
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail("AdminAuth:ApiKeyPepper must be configured with at least 32 characters.");
    }
}
