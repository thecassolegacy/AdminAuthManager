using AdminAuth.Entities;
using Microsoft.EntityFrameworkCore;

namespace AdminAuth.Persistence;

public class AdminAuthDbContext : DbContext
{
    public AdminAuthDbContext(DbContextOptions<AdminAuthDbContext> options) : base(options)
    {
    }

    protected AdminAuthDbContext(DbContextOptions options) : base(options)
    {
    }

    public DbSet<AdminUser> AdminUsers => Set<AdminUser>();

    public DbSet<AdminPermission> AdminPermissions => Set<AdminPermission>();

    public DbSet<AdminUserPermission> AdminUserPermissions => Set<AdminUserPermission>();

    public DbSet<AdminTotpAuthenticator> AdminTotpAuthenticators => Set<AdminTotpAuthenticator>();

    public DbSet<AdminApiKey> AdminApiKeys => Set<AdminApiKey>();

    public DbSet<AdminTotpRecoveryCode> AdminTotpRecoveryCodes => Set<AdminTotpRecoveryCode>();

    public DbSet<AdminAuditEntry> AdminAuditEntries => Set<AdminAuditEntry>();

    protected virtual string? Schema => null;

    public static string NormalizeName(string value) => value.Trim().ToUpperInvariant();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        if (!string.IsNullOrWhiteSpace(Schema))
        {
            modelBuilder.HasDefaultSchema(Schema);
        }

        modelBuilder.Entity<AdminUser>(entity =>
        {
            entity.ToTable("AdminUsers");
            entity.HasKey(user => user.Id);
            entity.Property(user => user.UserName).HasMaxLength(256).IsRequired();
            entity.Property(user => user.NormalizedUserName).HasMaxLength(256).IsRequired();
            entity.Property(user => user.ConcurrencyStamp).HasMaxLength(32).IsConcurrencyToken();
            entity.HasIndex(user => user.NormalizedUserName).IsUnique();
            entity.HasIndex(user => new { user.IsActive, user.IsSuperAdmin });
            entity.HasMany(user => user.Permissions)
                .WithOne(permission => permission.AdminUser)
                .HasForeignKey(permission => permission.AdminUserId)
                .OnDelete(DeleteBehavior.Cascade);
            entity.HasMany(user => user.ApiKeys)
                .WithOne(key => key.AdminUser)
                .HasForeignKey(key => key.AdminUserId)
                .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(user => user.TotpAuthenticator)
                .WithOne(authenticator => authenticator.AdminUser)
                .HasForeignKey<AdminTotpAuthenticator>(authenticator => authenticator.AdminUserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AdminPermission>(entity =>
        {
            entity.ToTable("AdminPermissions");
            entity.HasKey(permission => permission.Id);
            entity.Property(permission => permission.Name).HasMaxLength(256).IsRequired();
            entity.Property(permission => permission.NormalizedName).HasMaxLength(256).IsRequired();
            entity.Property(permission => permission.Description).HasMaxLength(1_024);
            entity.HasIndex(permission => permission.NormalizedName).IsUnique();
            entity.HasMany(permission => permission.Users)
                .WithOne(user => user.AdminPermission)
                .HasForeignKey(user => user.AdminPermissionId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AdminUserPermission>(entity =>
        {
            entity.ToTable("AdminUserPermissions");
            entity.HasKey(permission => new { permission.AdminUserId, permission.AdminPermissionId });
        });

        modelBuilder.Entity<AdminTotpAuthenticator>(entity =>
        {
            entity.ToTable("AdminTotpAuthenticators");
            entity.HasKey(authenticator => authenticator.AdminUserId);
            entity.Property(authenticator => authenticator.ProtectedSecret).HasMaxLength(4_096).IsRequired();
            entity.Property(authenticator => authenticator.ConcurrencyStamp).HasMaxLength(32).IsConcurrencyToken();
        });

        modelBuilder.Entity<AdminApiKey>(entity =>
        {
            entity.ToTable("AdminApiKeys");
            entity.HasKey(key => key.Id);
            entity.Property(key => key.Prefix).HasMaxLength(16).IsRequired();
            entity.Property(key => key.KeyHash).HasMaxLength(64).IsRequired();
            entity.HasIndex(key => key.Prefix).IsUnique();
            entity.HasIndex(key => key.AdminUserId);
        });

        modelBuilder.Entity<AdminAuditEntry>(entity =>
        {
            entity.ToTable("AdminAuditEntries");
            entity.HasKey(audit => audit.Id);
            entity.Property(audit => audit.Action).HasMaxLength(64).IsRequired();
            entity.Property(audit => audit.Detail).HasMaxLength(512);
            entity.HasIndex(audit => audit.OccurredAtUtc);
            entity.HasIndex(audit => audit.ActorAdminUserId);
            entity.HasIndex(audit => audit.TargetAdminUserId);
        });

        modelBuilder.Entity<AdminTotpRecoveryCode>(entity =>
        {
            entity.ToTable("AdminTotpRecoveryCodes");
            entity.HasKey(code => code.Id);
            entity.Property(code => code.CodeHash).HasMaxLength(64).IsRequired();
            entity.HasIndex(code => new { code.AdminUserId, code.CodeHash }).IsUnique();
            entity.HasOne<AdminUser>()
                .WithMany()
                .HasForeignKey(code => code.AdminUserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        ApplyAuditAndNormalization();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override Task<int> SaveChangesAsync(
        bool acceptAllChangesOnSuccess,
        CancellationToken cancellationToken = default)
    {
        ApplyAuditAndNormalization();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    private void ApplyAuditAndNormalization()
    {
        var now = DateTimeOffset.UtcNow;

        foreach (var entry in ChangeTracker.Entries())
        {
            if (entry.State is not (EntityState.Added or EntityState.Modified))
            {
                continue;
            }

            switch (entry.Entity)
            {
                case AdminUser user:
                    user.NormalizedUserName = NormalizeName(user.UserName);
                    user.UpdatedAtUtc = now;
                    user.ConcurrencyStamp = Guid.NewGuid().ToString("N");
                    break;
                case AdminPermission permission:
                    permission.NormalizedName = NormalizeName(permission.Name);
                    break;
                case AdminTotpAuthenticator authenticator:
                    authenticator.ConcurrencyStamp = Guid.NewGuid().ToString("N");
                    break;
            }
        }
    }
}
