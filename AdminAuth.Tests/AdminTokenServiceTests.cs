using AdminAuth.Authentication;
using AdminAuth.Configuration;
using AdminAuth.Entities;
using AdminAuth.Persistence;
using AdminAuth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace AdminAuth.Tests;

public sealed class AdminTokenServiceTests : IAsyncLifetime
{
    private const string Signing = "0123456789abcdef0123456789abcdef-signing";

    private readonly SqliteConnection _connection = new("DataSource=:memory:");
    private AdminAuthDbContext _db = null!;
    private readonly StubTotp _totp = new();
    private readonly AdminAuthOptions _options = new()
    {
        ApiKeyPepper = new string('p', 40),
        Jwt = { Issuer = "iss", Audience = "aud", SigningKey = Signing }
    };

    public async Task InitializeAsync()
    {
        await _connection.OpenAsync();
        _db = new SqliteAdminAuthDbContext(new DbContextOptionsBuilder<SqliteAdminAuthDbContext>().UseSqlite(_connection).Options);
        await _db.Database.EnsureCreatedAsync();
    }

    public async Task DisposeAsync()
    {
        await _db.DisposeAsync();
        await _connection.DisposeAsync();
    }

    private AdminTokenService Service(IApiKeyService keys) => new(
        new EfCoreAdminUserStore(_db), keys, _totp, _db, Options.Create(_options),
        TimeProvider.System, NullLogger<AdminTokenService>.Instance);

    private async Task<(AdminUser User, string Key, ApiKeyService Keys)> SeedAsync(bool withTotp = false)
    {
        var keys = new ApiKeyService(Options.Create(_options));
        var generated = keys.Generate();
        var user = new AdminUser
        {
            UserName = "ops",
            ApiKeys = { new AdminApiKey { Prefix = generated.Prefix, KeyHash = generated.KeyHash } }
        };
        _db.AdminUsers.Add(user);
        await _db.SaveChangesAsync();

        if (withTotp)
        {
            _db.AdminTotpAuthenticators.Add(new AdminTotpAuthenticator
            {
                AdminUserId = user.Id,
                ProtectedSecret = "x",
                IsEnabled = true
            });
            await _db.SaveChangesAsync();
        }

        return (user, generated.PlainTextKey, keys);
    }

    [Fact]
    public async Task IssuesValidToken_WithoutMfaClaim_WhenNoFactorEnrolled()
    {
        var (user, key, keys) = await SeedAsync();

        var result = await Service(keys).IssueTokenAsync(key);

        Assert.True(result.Succeeded);
        Assert.False(result.MfaSatisfied);

        var configured = new JwtBearerOptions();
        new AdminJwtBearerPostConfigure(Options.Create(_options)).PostConfigure(JwtBearerDefaults.AuthenticationScheme, configured);
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(result.Token!, configured.TokenValidationParameters);

        Assert.True(validation.IsValid);
        Assert.Equal(user.Id.ToString(), validation.ClaimsIdentity.FindFirst(JwtRegisteredClaimNames.Sub)?.Value);
        Assert.Null(validation.ClaimsIdentity.FindFirst("admin_mfa"));
    }

    [Fact]
    public async Task RequiresMfa_ThenIssuesMfaClaim_WhenCodeIsValid()
    {
        var (_, key, keys) = await SeedAsync(withTotp: true);
        var service = Service(keys);

        var missing = await service.IssueTokenAsync(key);
        Assert.True(missing.MfaRequired);
        Assert.Null(missing.Token);

        _totp.ValidCode = "123456";
        Assert.False((await service.IssueTokenAsync(key, "000000")).Succeeded);

        var ok = await service.IssueTokenAsync(key, "123456");
        Assert.True(ok.Succeeded);
        Assert.True(ok.MfaSatisfied);

        var token = new JsonWebTokenHandler().ReadJsonWebToken(ok.Token);
        Assert.Equal(bool.TrueString, token.GetClaim("admin_mfa").Value);
    }

    [Fact]
    public async Task RejectsBadKeys_AndLocksOutAfterRepeatedFailures()
    {
        var (user, key, keys) = await SeedAsync();
        var service = Service(keys);
        var wrong = key[..key.IndexOf('.')] + ".wrongsecret";

        Assert.False((await service.IssueTokenAsync("garbage")).Succeeded);
        Assert.False((await service.IssueTokenAsync("abc.def")).Succeeded);

        for (var i = 0; i < _options.MaxFailedAccessAttempts; i++)
        {
            Assert.False((await service.IssueTokenAsync(wrong)).Succeeded);
        }

        Assert.False((await service.IssueTokenAsync(key)).Succeeded);
        Assert.NotNull((await _db.AdminUsers.AsNoTracking().SingleAsync(u => u.Id == user.Id)).LockoutEndUtc);
    }

    [Fact]
    public async Task RejectsRevokedKeys_AndInactiveUsers()
    {
        var (user, key, keys) = await SeedAsync();
        var service = Service(keys);

        await _db.AdminApiKeys.Where(k => k.AdminUserId == user.Id)
            .ExecuteUpdateAsync(s => s.SetProperty(k => k.RevokedAtUtc, DateTimeOffset.UtcNow));
        Assert.False((await service.IssueTokenAsync(key)).Succeeded);

        await _db.AdminApiKeys.Where(k => k.AdminUserId == user.Id)
            .ExecuteUpdateAsync(s => s.SetProperty(k => k.RevokedAtUtc, (DateTimeOffset?)null));
        await _db.AdminUsers.Where(u => u.Id == user.Id)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.IsActive, false));
        Assert.False((await service.IssueTokenAsync(key)).Succeeded);
    }

    [Fact]
    public void Validator_RequiresStrongSigningKey()
    {
        var validator = new AdminAuthOptionsValidator();
        _options.Jwt.SigningKey = "short";
        Assert.True(validator.Validate(null, _options).Failed);

        _options.Jwt.SigningKey = Signing;
        Assert.True(validator.Validate(null, _options).Succeeded);
    }

    private sealed class StubTotp : ITotpService
    {
        public string? ValidCode { get; set; }

        public Task<TotpEnrollment> BeginSetupAsync(Guid administratorId, string? currentCode = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<TotpConfirmationResult> ConfirmSetupAsync(Guid administratorId, string code, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<bool> VerifyCodeAsync(Guid administratorId, string code, CancellationToken cancellationToken = default) => Task.FromResult(code == ValidCode);

        public Task<bool> VerifyRecoveryCodeAsync(Guid administratorId, string recoveryCode, CancellationToken cancellationToken = default) => Task.FromResult(false);

        public Task<bool> DisableAsync(Guid administratorId, string codeOrRecoveryCode, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task ResetAsync(Guid actingAdministratorId, Guid targetAdministratorId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }
}
