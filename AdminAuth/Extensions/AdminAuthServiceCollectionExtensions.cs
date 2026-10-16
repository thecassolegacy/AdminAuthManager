using AdminAuth.Authentication;
using AdminAuth.Authorization;
using AdminAuth.Configuration;
using AdminAuth.Persistence;
using AdminAuth.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AdminAuth.Extensions;

public static class AdminAuthServiceCollectionExtensions
{
    public const string AuthenticationScheme = "AdminAuth";

    public static IServiceCollection AddAdminAuth(
        this IServiceCollection services,
        Action<JwtBearerOptions> configureJwtBearer,
        Action<AdminAuthOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureJwtBearer);

        services.AddOptions<AdminAuthOptions>().ValidateOnStart();
        services.AddOptions<TotpOptions>().ValidateOnStart();
        services.AddSingleton<IValidateOptions<AdminAuthOptions>, AdminAuthOptionsValidator>();
        services.AddSingleton<IValidateOptions<TotpOptions>, TotpOptionsValidator>();
        services.AddSingleton(TimeProvider.System);

        var settings = new AdminAuthOptions();
        configure?.Invoke(settings);

        if (configure is not null)
        {
            services.Configure(configure);
        }

        services.AddDataProtection().SetApplicationName(settings.DataProtectionApplicationName);
        services.AddSingleton<IValidateOptions<JwtBearerOptions>, JwtBearerOptionsValidator>();
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme).ValidateOnStart();

        services.AddScoped<IAdminUserStore, EfCoreAdminUserStore>();
        services.AddSingleton<IApiKeyService, ApiKeyService>();
        services.AddScoped<IPermissionManagementService, PermissionManagementService>();
        services.AddScoped<ITotpService, TotpService>();
        services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler>();
        services.AddScoped<IAdministratorManagementService, AdministratorManagementService>();
        services.AddSingleton<IAuthorizationHandler, SuperAdminAuthorizationHandler>();
        services.AddSingleton<IAuthorizationHandler, MfaAuthorizationHandler>();
        services.AddScoped<IClaimsTransformation, AdminClaimsTransformation>();

        services.AddAuthentication(authenticationOptions =>
            {
                if (settings.SetAsDefaultScheme)
                {
                    authenticationOptions.DefaultAuthenticateScheme = AuthenticationScheme;
                    authenticationOptions.DefaultChallengeScheme = AuthenticationScheme;
                }
            })
            .AddPolicyScheme(AuthenticationScheme, AuthenticationScheme, policyOptions =>
            {
                policyOptions.ForwardDefaultSelector = context =>
                    context.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                        ? JwtBearerDefaults.AuthenticationScheme
                        : ApiKeyAuthenticationDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, configureJwtBearer)
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
                ApiKeyAuthenticationDefaults.AuthenticationScheme,
                _ => { });

        services.AddAuthorization();

        return services;
    }

    public static AuthorizationOptions AddAdminPermissionPolicy(
        this AuthorizationOptions options,
        string policyName,
        string permission)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);

        options.AddPolicy(policyName, policy =>
        {
            policy.AddAuthenticationSchemes(AuthenticationScheme);
            policy.RequireAuthenticatedUser();
            policy.Requirements.Add(new PermissionRequirement(permission));
        });

        return options;
    }

    /// <summary>
    /// Adds a permission policy that also requires MFA for JWT callers. API-key callers are exempt.
    /// </summary>
    public static AuthorizationOptions AddAdminPermissionPolicyWithMfa(
        this AuthorizationOptions options,
        string policyName,
        string permission)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);

        options.AddPolicy(policyName, policy =>
        {
            policy.AddAuthenticationSchemes(AuthenticationScheme);
            policy.RequireAuthenticatedUser();
            policy.Requirements.Add(new PermissionRequirement(permission));
            policy.Requirements.Add(new MfaRequirement());
        });

        return options;
    }

    /// <summary>
    /// Adds a super-admin policy that also requires MFA for JWT callers. API-key callers are exempt.
    /// </summary>
    public static AuthorizationOptions AddSuperAdminPolicyWithMfa(
        this AuthorizationOptions options,
        string policyName = "Admin.SuperAdmin.Mfa")
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);

        options.AddPolicy(policyName, policy =>
        {
            policy.AddAuthenticationSchemes(AuthenticationScheme);
            policy.RequireAuthenticatedUser();
            policy.Requirements.Add(new SuperAdminRequirement());
            policy.Requirements.Add(new MfaRequirement());
        });

        return options;
    }

    public static AuthorizationOptions AddSuperAdminPolicy(
        this AuthorizationOptions options,
        string policyName = "Admin.SuperAdmin")
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);

        options.AddPolicy(policyName, policy =>
        {
            policy.AddAuthenticationSchemes(AuthenticationScheme);
            policy.RequireAuthenticatedUser();
            policy.Requirements.Add(new SuperAdminRequirement());
        });

        return options;
    }
}
