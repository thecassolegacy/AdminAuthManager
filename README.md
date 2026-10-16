# AdminAuth

AdminAuth is a .NET 10 ASP.NET Core library for securing administrative endpoints. It authenticates administrators with JWT bearer tokens or database-backed API keys, stores administrators, permissions, API keys and TOTP factors with EF Core, and enforces permissions through standard ASP.NET Core authorization policies.

## Features

- JWT bearer and API-key authentication behind a single `AdminAuth` scheme.
- API keys in `<prefix>.<secret>` form. Only a peppered HMAC-SHA256 of the secret is stored, compared in constant time.
- API key expiry, revocation, last-used tracking, and per-administrator lockout after repeated failures.
- Permission-based authorization policies, plus a super-admin policy.
- Guarded permission creation by super administrators (`IPermissionManagementService`).
- TOTP enrollment compatible with RFC 6238 authenticator apps, with recovery codes, lockout and replay protection (`ITotpService`).
- Normalized names, concurrency tokens and an optional database schema.
- Replaceable API-key store (`IAdminUserStore`).

## Current limitations

- **JWT subjects are revalidated, but the MFA claim is trusted.** On every request a claims transformation looks up the token's subject (`sub` / `NameIdentifier`). Unknown or inactive administrators lose all claims, and `admin_permission` and `admin_super_admin` claims are replaced with the database values. The `admin_mfa` claim is taken from the token, so only a trusted issuer may set it, after verifying a TOTP code.
- **TOTP applies to JWT callers only.** `ITotpService` enrolls and verifies codes. The MFA policies require the `admin_mfa` claim on JWT callers; API-key callers are exempt by design.
- **Super administrators do not bypass permission policies.** This is a deliberate decision: they need the permissions they use, and `AddSuperAdminPolicy` only checks the super-admin flag.
- **Lockout is per administrator.** Someone who knows a key's prefix can trigger a lockout. Add IP-based rate limiting in your application.

## Prerequisites

- .NET 10 SDK and an ASP.NET Core application.
- An EF Core provider in the consuming application, such as `Microsoft.EntityFrameworkCore.SqlServer`.
- A secret store for the API-key pepper and JWT signing key.
- A persistent, shared Data Protection key ring if you use TOTP.

## Install and reference

Until the library is published as a NuGet package, reference the project directly:

```xml
<ItemGroup>
  <ProjectReference Include="..\AdminAuth\AdminAuth.csproj" />
</ItemGroup>
```

```powershell
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
dotnet add package Microsoft.EntityFrameworkCore.Design
```

## Configure services

```csharp
using System.Text;
using AdminAuth.Configuration;
using AdminAuth.Extensions;
using AdminAuth.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AdminAuthDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AdminAuth")));

builder.Services.AddAdminAuth(
    jwt =>
    {
        jwt.RequireHttpsMetadata = true;
        jwt.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidateAudience = true,
            ValidAudience = builder.Configuration["Jwt:Audience"],
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SigningKey"]!))
        };
    },
    options =>
    {
        options.ApiKeyHeaderName = "X-Admin-Api-Key";
        options.ApiKeyPepper = builder.Configuration["AdminAuth:ApiKeyPepper"]!;
    });

builder.Services.Configure<TotpOptions>(options => options.Issuer = "Contoso Admin");

builder.Services.AddAuthorization(options =>
{
    options.AddAdminPermissionPolicy("Admin.Users.Read", "admin.users.read");
    options.AddAdminPermissionPolicy("Admin.Users.Write", "admin.users.write");
    options.AddSuperAdminPolicy(); // policy name: "Admin.SuperAdmin"
});

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.Run();
```

`AddAdminAuth`:

- Registers the `AdminAuth` scheme. It becomes the application's default authenticate and challenge scheme only when `SetAsDefaultScheme = true`; the policy helpers always select `AdminAuth` explicitly, so existing defaults are not overridden.
- Routes requests with an `Authorization: Bearer ...` header to JWT bearer. All other requests are evaluated as API-key authentication.
- Registers `IAdminUserStore`, `IApiKeyService`, `IPermissionManagementService`, `IAdministratorManagementService`, `ITotpService`, the authorization handlers, the JWT revalidation claims transformation, `TimeProvider.System` and Data Protection (with `DataProtectionApplicationName`).
- Validates `AdminAuthOptions`, `TotpOptions` and the JWT bearer options at startup; invalid values prevent the app from starting.

## Configuration reference

### `AdminAuthOptions`

| Option | Default | Description |
| --- | --- | --- |
| `ApiKeyHeaderName` | `X-Api-Key` | Header carrying the API key. |
| `ApiKeyPepper` | none | **Required**, at least 32 characters. Secret mixed into API-key and recovery-code hashes. Keep it outside the database and source control. Changing it invalidates all API keys and recovery codes. |
| `MaxFailedAccessAttempts` | `5` | Wrong secrets (3 to 100) before lockout. |
| `DataProtectionApplicationName` | `AdminAuth` | Data Protection application discriminator for TOTP secrets. Keep it identical on every instance and never change it after enrollment. |
| `SetAsDefaultScheme` | `false` | When `true`, `AdminAuth` becomes the app's default authenticate/challenge scheme. Otherwise your defaults are kept and the policy helpers still select `AdminAuth`. |
| `AllowInsecureJwtMetadata` | `false` | Permits `RequireHttpsMetadata = false` (development only). |
| `LockoutDuration` | 15 minutes | Minimum 1 minute. |
| `LastUsedUpdateInterval` | 5 minutes | Minimum time between last-used writes. |

### `TotpOptions`

| Option | Default | Description |
| --- | --- | --- |
| `Issuer` | `AdminAuth` | Name shown in the authenticator app. |
| `PeriodSeconds` | `30` | 15 to 120. |
| `Digits` | `6` | `6` or `8`. |
| `AllowedClockSkewSteps` | `1` | Earlier steps also accepted, 0 to 2. Future steps are rejected. |
| `MaxFailedAttempts` | `5` | 3 to 20 wrong codes before the factor locks. |
| `LockoutDuration` | 5 minutes | Minimum 1 minute. |
| `RecoveryCodeCount` | `10` | 5 to 20. |

Many authenticator apps ignore non-default `PeriodSeconds` and `Digits`. Keep the defaults unless you control every client; changing them after enrollment breaks enrolled factors.

## Configure the database

| Table | Purpose |
| --- | --- |
| `AdminUsers` | Administrators: name, normalized name, active and super-admin flags, lockout state, concurrency stamp, timestamps. |
| `AdminApiKeys` | API keys: public prefix, peppered hash, expiry, revocation, last-used time. |
| `AdminPermissions` | Named permissions with a unique normalized name. |
| `AdminUserPermissions` | Assignments, including who granted them. |
| `AdminTotpAuthenticators` | Protected TOTP secret, state, replay marker, lockout state. |
| `AdminTotpRecoveryCodes` | Hashed single-use recovery codes. |
| `AdminAuditEntries` | Append-only audit log of grants, revocations, promotions and demotions. |

```powershell
dotnet ef migrations add AddAdminAuth --context AdminAuthDbContext
dotnet ef database update --context AdminAuthDbContext
```

Names are trimmed and upper-cased into the `Normalized*` columns during `SaveChanges`, and uniqueness is enforced on those. Bulk operations such as `ExecuteUpdate` bypass this, so change names through tracked entities.

### Using your own DbContext

Derive from `AdminAuthDbContext` with the protected constructor, call `base.OnModelCreating`, and optionally override `Schema`:

```csharp
public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : AdminAuthDbContext(options)
{
    protected override string? Schema => "admin";

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        // application entities
    }
}
```

The library services depend on `AdminAuthDbContext`, so also map that type to your context:

```csharp
builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlServer(connectionString));
builder.Services.AddScoped<AdminAuthDbContext>(sp => sp.GetRequiredService<AppDbContext>());
```

## Bootstrap the first super administrator

Creating permissions requires a super administrator, and the library cannot create the first one. Seed it once from a trusted context (a one-off command or a temporary startup task):

```csharp
using AdminAuth.Authentication;
using AdminAuth.Entities;
using AdminAuth.Persistence;

static async Task<string> CreateFirstSuperAdminAsync(
    AdminAuthDbContext dbContext,
    IApiKeyService apiKeys,
    CancellationToken cancellationToken = default)
{
    var key = apiKeys.Generate();

    dbContext.AdminUsers.Add(new AdminUser
    {
        UserName = "platform-admin",
        IsSuperAdmin = true,
        ApiKeys =
        {
            new AdminApiKey
            {
                Prefix = key.Prefix,
                KeyHash = key.KeyHash,
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddDays(90)
            }
        }
    });

    await dbContext.SaveChangesAsync(cancellationToken);

    return key.PlainTextKey; // show once; never log or store
}
```

## Provision administrators and API keys

`IApiKeyService.Generate()` returns a `GeneratedApiKey` with `PlainTextKey`, `Prefix` and `KeyHash`. Persist only `Prefix` and `KeyHash`, and give `PlainTextKey` to the administrator once through a secure channel. It cannot be recovered.

Create permissions first, then assign them:

```csharp
static async Task<string> CreateAdministratorAsync(
    AdminAuthDbContext dbContext,
    IApiKeyService apiKeys,
    string userName,
    IEnumerable<string> permissionNames,
    Guid grantedByAdministratorId,
    CancellationToken cancellationToken = default)
{
    var wanted = permissionNames.Select(AdminAuthDbContext.NormalizeName).ToList();

    var permissions = await dbContext.AdminPermissions
        .Where(permission => wanted.Contains(permission.NormalizedName))
        .ToListAsync(cancellationToken);

    var key = apiKeys.Generate();

    dbContext.AdminUsers.Add(new AdminUser
    {
        UserName = userName,
        Permissions = permissions.Select(permission => new AdminUserPermission
        {
            AdminPermission = permission,
            GrantedByAdminUserId = grantedByAdministratorId
        }).ToList(),
        ApiKeys =
        {
            new AdminApiKey
            {
                Prefix = key.Prefix,
                KeyHash = key.KeyHash,
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddDays(90)
            }
        }
    });

    await dbContext.SaveChangesAsync(cancellationToken);

    return key.PlainTextKey;
}
```

Key management:

- **Rotate:** add a new `AdminApiKey`, move the client over, then set `RevokedAtUtc` on the old one. Several active keys per administrator are allowed.
- **Revoke:** set `RevokedAtUtc`. Revoked and expired keys are rejected.
- **Disable an administrator:** set `IsActive = false`. API keys stop working immediately; existing JWTs work until they expire.
- **Unlock:** clear `LockoutEndUtc` and set `FailedAccessCount` to `0`.
- **Last use:** `AdminApiKey.LastUsedAtUtc` and `AdminUser.LastAuthenticatedAtUtc` are updated at most once per `LastUsedUpdateInterval`.

## Authenticate with an API key

Send the full `<prefix>.<secret>` value in the configured header, once per request:

```http
GET /admin/users HTTP/1.1
Host: example.test
X-Admin-Api-Key: <prefix>.<secret>
```

The library looks up the key by prefix, verifies the secret in constant time, and checks that the key is not revoked or expired, the administrator is active, and the administrator is not locked out. It then issues claims for the administrator ID, name, super-admin status and each assigned permission, read from the database on every request.

All failures return the same `401` response. Keys longer than 128 characters are rejected.

## Authenticate with JWT

Tokens must satisfy the `JwtBearerOptions` you pass to `AddAdminAuth`. Startup fails unless the options enable HTTPS metadata, issuer, audience, lifetime (with expiration required), signature and signing-key validation, list explicit `ValidAlgorithms` (never `none`), and keep `ClockSkew` at 5 minutes or less.

The token needs a `sub` (or `NameIdentifier`) claim holding the administrator's GUID. On each request the library loads that administrator: unknown or inactive administrators lose all claims, and `admin_permission` and `admin_super_admin` are **replaced with the database values**, so token claims for these only matter for issuer convenience. A trusted issuer sets `admin_mfa` to `True` after verifying a TOTP code:

```json
{
  "sub": "5b2f9c1e-3c7b-4f4e-9d2a-0d6f0f6a1111",
  "name": "ops-admin",
  "admin_mfa": "True"
}
```

Claim types are available as `AdminAuthClaimTypes.Permission`, `SuperAdmin` and `Mfa`. Permission values are compared exactly (case-sensitive).

Features that look up the administrator, such as permission creation and TOTP, read the ID from the `NameIdentifier` claim. JWTs should carry the administrator's GUID as `sub`, which the default inbound claim mapping maps to `ClaimTypes.NameIdentifier`.

## Protect endpoints

Use the policy names registered with `AddAdminPermissionPolicy`.

```csharp
app.MapGet("/admin/users", GetAdministrators)
    .RequireAuthorization("Admin.Users.Read");
```

```csharp
[ApiController]
[Route("admin/users")]
public sealed class AdminUsersController : ControllerBase
{
    [HttpGet]
    [Authorize(Policy = "Admin.Users.Read")]
    public IActionResult Get() => Ok();
}
```

ASP.NET Core returns `401` for unauthenticated callers and `403` for authenticated callers without the permission.

### Requiring MFA

```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddAdminPermissionPolicyWithMfa("Admin.Users.Write", "admin.users.write");
    options.AddSuperAdminPolicyWithMfa(); // policy name: "Admin.SuperAdmin.Mfa"
});
```

These add `MfaRequirement`, which JWT callers satisfy only with the `admin_mfa` claim. API-key callers are exempt because TOTP is not used for API keys. You can also add `new MfaRequirement()` to your own policies.

## Super administrators and permission management

`IsSuperAdmin` is a database flag set during provisioning. `IPermissionManagementService.CreatePermissionAsync` verifies in the database (not only the token) that the acting administrator exists, is active and is a super administrator. It trims input, limits names and descriptions to the column sizes, and rejects duplicates using the normalized name, so duplicates differing only by case are rejected.

```csharp
app.MapPost("/admin/permissions", async (
    CreatePermissionRequest request,
    ClaimsPrincipal user,
    IPermissionManagementService permissions,
    CancellationToken cancellationToken) =>
{
    if (!Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out var administratorId))
    {
        return Results.Forbid();
    }

    try
    {
        var permission = await permissions.CreatePermissionAsync(
            administratorId, request.Name, request.Description, cancellationToken);

        return Results.Created(
            $"/admin/permissions/{permission.Id}",
            new PermissionResponse(permission.Id, permission.Name, permission.Description));
    }
    catch (UnauthorizedAccessException)
    {
        return Results.Forbid();
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
    catch (Exception ex) when (ex is InvalidOperationException or DbUpdateException)
    {
        return Results.Conflict(new { error = "The permission already exists." });
    }
}).RequireAuthorization("Admin.SuperAdmin");

public sealed record CreatePermissionRequest(string Name, string? Description);
public sealed record PermissionResponse(Guid Id, string Name, string? Description);
```

Return a DTO rather than the entity to avoid serializing navigation properties.

Permission names must be 1 to 128 characters of letters, digits, `.`, `_`, `:` or `-`, starting with a letter or digit. Duplicates are detected on the normalized name, and a race on the unique index is reported as `InvalidOperationException`.

### Granting, revoking, promoting and demoting

`IAdministratorManagementService` offers `GrantPermissionAsync`, `RevokePermissionAsync`, `PromoteAsync` and `DemoteAsync`. Each call:

- requires an active super administrator, checked in the database;
- rejects changes to the caller's own permissions or super-admin status (no self-promotion);
- refuses to demote the last active super administrator;
- runs in a serializable transaction and writes an `AdminAuditEntries` row.

It throws `UnauthorizedAccessException`, `KeyNotFoundException`, `InvalidOperationException` or `ArgumentException`; map these to `403`, `404`, `409` and `400`.

```csharp
app.MapPost("/admin/administrators/{id:guid}/permissions/{name}", async (
    Guid id, string name, ClaimsPrincipal user,
    IAdministratorManagementService management, CancellationToken ct) =>
{
    var actor = Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!);
    await management.GrantPermissionAsync(actor, id, name, ct);
    return Results.NoContent();
}).RequireAuthorization("Admin.SuperAdmin.Mfa");
```

Super administrators do not implicitly pass permission policies; grant them the permissions they need.

## TOTP authenticators

`ITotpService` supports any RFC 6238 authenticator app (Base32 secret, HMAC-SHA1, 6 digits, 30-second period).

### Enroll

```csharp
using AdminAuth.Services;

var enrollment = await totpService.BeginSetupAsync(administratorId, cancellationToken: cancellationToken);

// Render enrollment.ProvisioningUri as a QR code (otpauth://totp/...).
// Show enrollment.Secret only for manual entry; never log it.

var result = await totpService.ConfirmSetupAsync(administratorId, firstCode, cancellationToken);

if (result.Succeeded)
{
    // Show result.RecoveryCodes once. Only their hashes are stored.
}
```

The factor is enabled only after `ConfirmSetupAsync` succeeds. Calling `BeginSetupAsync` again before then discards the pending secret. If a factor is already enabled, `BeginSetupAsync` requires a valid `currentCode` to replace it, so an API key alone cannot replace the second factor.

### Verify

```csharp
var ok = await totpService.VerifyCodeAsync(administratorId, code, cancellationToken)
      || await totpService.VerifyRecoveryCodeAsync(administratorId, code, cancellationToken);
```

- The current step and up to `AllowedClockSkewSteps` earlier steps are accepted. A code cannot be reused, and concurrent submissions of the same code cannot both succeed.
- After `MaxFailedAttempts` wrong codes the factor locks for `LockoutDuration`.
- Each recovery code works once.

### Disable and reset

```csharp
// Self-service; needs a valid code or recovery code.
var disabled = await totpService.DisableAsync(administratorId, codeOrRecoveryCode, cancellationToken);

// A super administrator removes another administrator's lost factor.
await totpService.ResetAsync(actingAdministratorId, targetAdministratorId, cancellationToken);
```

`ResetAsync` requires an active super administrator and cannot target the caller. Verify the target's identity out of band first, because it removes the second factor.

### Protecting the secret

Secrets are encrypted with ASP.NET Core Data Protection. Persist and share the key ring, or enrolled factors become unreadable after a restart or on another instance:

```csharp
builder.Services.AddDataProtection()
    .SetApplicationName("Contoso.Admin")
    .PersistKeysToFileSystem(new DirectoryInfo("/secure/adminauth-keyring"));
```

Use a shared, access-controlled store for multi-instance deployments and protect the key ring itself.

## Replace API-key persistence

The default `EfCoreAdminUserStore` uses `AdminAuthDbContext`. To use another store, implement `IAdminUserStore` and register it after `AddAdminAuth`:

```csharp
builder.Services.AddScoped<IAdminUserStore, CustomAdminUserStore>();
```

- `FindApiKeyByPrefixAsync(prefix, ct)` returns the `AdminApiKey` with its `AdminUser`, that user's `Permissions`, and each `AdminPermission` loaded.
- `RecordFailedAttemptAsync(adminUserId, maxAttempts, lockoutDuration, now, ct)` must increment the failure count atomically and lock the administrator when the limit is reached.
- `RecordSuccessAsync(apiKeyId, adminUserId, now, minInterval, ct)` must clear failure and lockout state and record last-used times, skipping writes newer than `minInterval`.

## Deployment and operations

- Use HTTPS everywhere; API keys and bearer tokens are credentials.
- Keep the API-key pepper, JWT signing key and Data Protection keys in a managed secret store, separate from the database.
- Give each person or automation client its own administrator and key, and expire keys regularly.
- Grant minimum permissions and review grants and super administrators regularly.
- Add IP rate limiting in front of admin endpoints.
- Monitor the "Admin API key rejected ..." warning logs. They include administrator ID, key ID and client IP, never key material.
- Keep JWT lifetimes short, since JWT claims are not rechecked against the database.
- Commit EF Core migrations to source control and apply them through your normal deployment process.

## Upgrading from earlier versions

This version has breaking changes.

- **API keys:** the `ApiKeyHash` column and `ApiKeyHasher` are removed. Original secrets were never stored, so existing keys cannot be converted. Issue new keys with `IApiKeyService.Generate()`.
- **Pepper:** `AdminAuthOptions.ApiKeyPepper` is required.
- **Normalized names:** `NormalizedUserName` and `NormalizedName` are new required columns. Backfill them with the upper-cased, trimmed name and resolve names that collide ignoring case before the unique indexes are applied.
- **`IAdminUserStore`:** `FindByApiKeyHashAsync` is replaced by `FindApiKeyByPrefixAsync`, `FindAdministratorAsync`, `RecordFailedAttemptAsync` and `RecordSuccessAsync`. Custom stores must implement `FindAdministratorAsync` (administrator with `Permissions` and each `AdminPermission` loaded).
- **Default scheme:** `AdminAuth` is no longer set as the default scheme unless `AdminAuthOptions.SetAsDefaultScheme = true`. Add `[Authorize(AuthenticationSchemes = "AdminAuth")]` or use the policy helpers.
- **JWT validation:** startup now fails for weak JWT options (see above).
- **Data Protection:** the application name defaults to `AdminAuth`. If you previously relied on the default application discriminator, set `DataProtectionApplicationName` to match your earlier value, or users must re-enroll TOTP.
- **Permission names:** names are now validated (letters, digits, `.`, `_`, `:`, `-`). Review existing names before upgrading.
- **New table:** `AdminAuditEntries`.
- **`ITotpService`:** `ConfirmSetupAsync` returns `TotpConfirmationResult` with recovery codes, `BeginSetupAsync` takes an optional current code, and `ResetAsync` takes acting and target IDs.
- **`AdminAuthDbContext`:** the public constructor takes `DbContextOptions<AdminAuthDbContext>`; derived contexts use the protected constructor.
- **New tables and columns:** `AdminApiKeys`, `AdminTotpRecoveryCodes`, plus lockout, concurrency and audit columns. Generate and review a migration before deploying.
