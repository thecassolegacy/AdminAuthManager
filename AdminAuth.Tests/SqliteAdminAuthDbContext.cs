using AdminAuth.Persistence;
using Microsoft.EntityFrameworkCore;

namespace AdminAuth.Tests;

/// <summary>
/// SQLite cannot compare DateTimeOffset values in SQL, so the tests store them as UTC ticks.
/// </summary>
public sealed class SqliteAdminAuthDbContext(DbContextOptions<SqliteAdminAuthDbContext> options)
    : AdminAuthDbContext(options)
{
    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        configurationBuilder.Properties<DateTimeOffset>().HaveConversion<long>();
        configurationBuilder.Properties<DateTimeOffset?>().HaveConversion<long?>();
    }
}
