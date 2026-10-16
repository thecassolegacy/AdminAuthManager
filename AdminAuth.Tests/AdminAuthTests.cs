using AdminAuth.Authentication;
using AdminAuth.Authorization;
using AdminAuth.Configuration;
using AdminAuth.Entities;
using AdminAuth.Persistence;
using AdminAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace AdminAuth.Tests;

public sealed class AdminAuthTests : IAsyncLifetime
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");
    private AdminAuthDbContext _db = null!;

    public async Task InitializeAsync()
    {
        await _connection.OpenAsync();
        _db = NewContext();
        await _db.Database.EnsureCreatedAsync();
    }

    public async Task DisposeAsync()
    {
        await _db.DisposeAsync();
        await _connection.DisposeAsync();
    }

    private AdminAuthDbContext NewContext() => new SqliteAdminAuthDbContext(
        new DbContextOptionsBuilder<SqliteAdminAuthDbContext>().UseSqlite(_connection).Options);

    private async Task<AdminUser> AddUserAsync(string name, bool superAdmin = false, bool active = true)
    {
        var user = new AdminUser { UserName = name, IsSuperAdmin = superAdmin, IsActive = active };
        _db.AdminUsers.Add(user);
        await _db.SaveChangesAsync();
        return user;
    }

    private static IOptions<AdminAuthOptions> Opts() =>
        Options.Create(new AdminAuthOptions { ApiKeyPepper = new string('p', 40) });

    [Fact]
    public void ApiKey_RoundTrips_AndRejectsWrongSecret()
    {
        var service = new ApiKeyService(Opts());
        var key = service.Generate();

        Assert.True(service.TryParse(key.PlainTextKey, out var prefix, out var secret));
        Assert.Equal(key.Prefix, prefix);
        Assert.True(service.Verify(secret, key.KeyHash));
        Assert.False(service.Verify(secret + "x", key.KeyHash));
        Assert.False(service.TryParse(new string('a', 200), out _, out _));
        Assert.False(service.TryParse("nodot", out _, out _));
    }

    [Fact]
    public async Task CreatePermission_RejectsInvalidNames_AndCaseInsensitiveDuplicates()
    {
        var admin = await AddUserAsync("root", superAdmin: true);
        var service = new PermissionManagementService(_db);

        await service.CreatePermissionAsync(admin.Id, "Users.Read");

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.CreatePermissionAsync(admin.Id, "users.read"));
        await Assert.ThrowsAsync<ArgumentException>(() => service.CreatePermissionAsync(admin.Id, "bad name!"));
    }

    [Fact]
    public async Task CreatePermission_RequiresActiveSuperAdmin()
    {
        var normal = await AddUserAsync("normal");
        var service = new PermissionManagementService(_db);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => service.CreatePermissionAsync(normal.Id, "a.b"));
    }

    [Fact]
    public async Task Management_GrantRevoke_WritesAuditAndBlocksSelfChange()
    {
        var root = await AddUserAsync("root", superAdmin: true);
        var target = await AddUserAsync("target");
        await new PermissionManagementService(_db).CreatePermissionAsync(root.Id, "Users.Read");
        var service = new AdministratorManagementService(_db);

        await service.GrantPermissionAsync(root.Id, target.Id, "users.read");
        Assert.Equal(1, await _db.AdminUserPermissions.CountAsync(p => p.AdminUserId == target.Id));

        await service.RevokePermissionAsync(root.Id, target.Id, "users.read");
        Assert.Equal(0, await _db.AdminUserPermissions.CountAsync(p => p.AdminUserId == target.Id));
        Assert.Equal(2, await _db.AdminAuditEntries.CountAsync());

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.GrantPermissionAsync(root.Id, root.Id, "users.read"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.PromoteAsync(root.Id, root.Id));
    }

    [Fact]
    public async Task Management_NonSuperAdmin_IsRejected()
    {
        var normal = await AddUserAsync("normal");
        var target = await AddUserAsync("target");

        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => new AdministratorManagementService(_db).PromoteAsync(normal.Id, target.Id));
    }

    [Fact]
    public async Task Management_ProtectsLastSuperAdmin_AllowsDemoteWhenAnotherExists()
    {
        var root = await AddUserAsync("root", superAdmin: true);
        var other = await AddUserAsync("other");
        var service = new AdministratorManagementService(_db);

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.DemoteAsync(root.Id, root.Id));

        await service.PromoteAsync(root.Id, other.Id);
        await service.DemoteAsync(other.Id, root.Id);

        Assert.False((await _db.AdminUsers.AsNoTracking().SingleAsync(u => u.Id == root.Id)).IsSuperAdmin);
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.DemoteAsync(other.Id, other.Id));
    }

    [Fact]
    public async Task ClaimsTransformation_ReplacesTokenClaims_AndStripsInactiveUsers()
    {
        var user = await AddUserAsync("jwt-user");
        var admin = await AddUserAsync("root", superAdmin: true);
        await new PermissionManagementService(_db).CreatePermissionAsync(admin.Id, "Users.Read");
        await new AdministratorManagementService(_db).GrantPermissionAsync(admin.Id, user.Id, "Users.Read");

        var transformation = new AdminClaimsTransformation(new EfCoreAdminUserStore(_db));

        ClaimsPrincipal Token(Guid id) => new(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, id.ToString()),
            new Claim(AdminAuthClaimTypes.SuperAdmin, bool.TrueString),
            new Claim(AdminAuthClaimTypes.Permission, "forged")
        ], "Bearer"));

        var result = await transformation.TransformAsync(Token(user.Id));
        Assert.False(result.HasClaim(AdminAuthClaimTypes.SuperAdmin, bool.TrueString));
        Assert.False(result.HasClaim(AdminAuthClaimTypes.Permission, "forged"));
        Assert.True(result.HasClaim(AdminAuthClaimTypes.Permission, "Users.Read"));

        var unknown = await transformation.TransformAsync(Token(Guid.NewGuid()));
        Assert.False(unknown.Identity?.IsAuthenticated ?? false);

        await _db.AdminUsers.Where(u => u.Id == user.Id)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.IsActive, false));
        var inactive = await transformation.TransformAsync(Token(user.Id));
        Assert.False(inactive.Identity?.IsAuthenticated ?? false);
    }

    [Fact]
    public async Task MfaHandler_RequiresClaimForJwt_ButNotForApiKey()
    {
        var handler = new MfaAuthorizationHandler();
        var requirement = new MfaRequirement();

        async Task<bool> Run(ClaimsIdentity identity)
        {
            var context = new AuthorizationHandlerContext([requirement], new ClaimsPrincipal(identity), null);
            await handler.HandleAsync(context);
            return context.HasSucceeded;
        }

        Assert.False(await Run(new ClaimsIdentity([], "Bearer")));
        Assert.True(await Run(new ClaimsIdentity([new Claim(AdminAuthClaimTypes.Mfa, bool.TrueString)], "Bearer")));
        Assert.True(await Run(new ClaimsIdentity([], ApiKeyAuthenticationDefaults.AuthenticationScheme)));
    }

    [Fact]
    public void JwtValidator_RejectsWeakOptions_AcceptsStrictOnes()
    {
        var validator = new JwtBearerOptionsValidator(Opts());

        var weak = new JwtBearerOptions { RequireHttpsMetadata = false };
        weak.TokenValidationParameters.ValidateIssuer = false;
        Assert.True(validator.Validate(JwtBearerDefaults.AuthenticationScheme, weak).Failed);

        var strict = new JwtBearerOptions { RequireHttpsMetadata = true };
        strict.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "issuer",
            ValidateAudience = true,
            ValidAudience = "aud",
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            ClockSkew = TimeSpan.FromMinutes(1),
            IssuerSigningKey = new SymmetricSecurityKey(new byte[32])
        };
        Assert.True(validator.Validate(JwtBearerDefaults.AuthenticationScheme, strict).Succeeded);
    }
}
