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

        if (!string.IsNullOrWhiteSpace(options.Jwt.SigningKey))
        {
            if (System.Text.Encoding.UTF8.GetByteCount(options.Jwt.SigningKey) < 32)
            {
                return ValidateOptionsResult.Fail("AdminAuth:Jwt:SigningKey must be at least 32 bytes.");
            }

            if (string.IsNullOrWhiteSpace(options.Jwt.Issuer) || string.IsNullOrWhiteSpace(options.Jwt.Audience))
            {
                return ValidateOptionsResult.Fail("AdminAuth:Jwt:Issuer and Audience must be configured.");
            }

            if (options.Jwt.TokenLifetime < TimeSpan.FromMinutes(1) || options.Jwt.TokenLifetime > TimeSpan.FromHours(12))
            {
                return ValidateOptionsResult.Fail("AdminAuth:Jwt:TokenLifetime must be between 1 minute and 12 hours.");
            }
        }

        return options.ApiKeyPepper is { Length: >= 32 }
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail("AdminAuth:ApiKeyPepper must be configured with at least 32 characters.");
    }
}
