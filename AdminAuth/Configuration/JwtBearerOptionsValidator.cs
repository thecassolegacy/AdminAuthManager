using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace AdminAuth.Configuration;

/// <summary>
/// Rejects weak JWT bearer configuration at startup.
/// </summary>
public sealed class JwtBearerOptionsValidator(IOptions<AdminAuthOptions> adminAuthOptions)
    : IValidateOptions<JwtBearerOptions>
{
    public ValidateOptionsResult Validate(string? name, JwtBearerOptions options)
    {
        if (name != JwtBearerDefaults.AuthenticationScheme)
        {
            return ValidateOptionsResult.Skip;
        }

        var parameters = options.TokenValidationParameters;
        var failures = new List<string>();

        if (!options.RequireHttpsMetadata && !adminAuthOptions.Value.AllowInsecureJwtMetadata)
        {
            failures.Add("JWT RequireHttpsMetadata must be true (or set AdminAuthOptions.AllowInsecureJwtMetadata for development).");
        }

        if (!parameters.ValidateIssuer
            || (string.IsNullOrWhiteSpace(parameters.ValidIssuer) && parameters.ValidIssuers?.Any() != true
                && string.IsNullOrWhiteSpace(options.Authority)))
        {
            failures.Add("JWT issuer validation must be enabled with ValidIssuer, ValidIssuers or Authority.");
        }

        if (!parameters.ValidateAudience
            || (string.IsNullOrWhiteSpace(parameters.ValidAudience) && parameters.ValidAudiences?.Any() != true))
        {
            failures.Add("JWT audience validation must be enabled with ValidAudience or ValidAudiences.");
        }

        if (!parameters.ValidateLifetime || !parameters.RequireExpirationTime)
        {
            failures.Add("JWT lifetime validation and RequireExpirationTime must be enabled.");
        }

        if (!parameters.ValidateIssuerSigningKey || !parameters.RequireSignedTokens)
        {
            failures.Add("JWT signing key validation and RequireSignedTokens must be enabled.");
        }

        if (parameters.IssuerSigningKey is null
            && parameters.IssuerSigningKeys?.Any() != true
            && string.IsNullOrWhiteSpace(options.Authority)
            && string.IsNullOrWhiteSpace(options.MetadataAddress))
        {
            failures.Add("JWT signing keys must be configured (IssuerSigningKey, IssuerSigningKeys, Authority or MetadataAddress).");
        }

        if (parameters.ValidAlgorithms?.Any() != true
            || parameters.ValidAlgorithms.Any(algorithm =>
                string.Equals(algorithm, "none", StringComparison.OrdinalIgnoreCase)))
        {
            failures.Add("JWT ValidAlgorithms must list the accepted signing algorithms and must not include 'none'.");
        }

        if (parameters.ClockSkew > TimeSpan.FromMinutes(5))
        {
            failures.Add("JWT ClockSkew must not exceed 5 minutes.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
