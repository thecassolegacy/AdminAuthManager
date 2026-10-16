namespace AdminAuth.Configuration;

public sealed class TotpOptions
{
    public string Issuer { get; set; } = "AdminAuth";

    public int PeriodSeconds { get; set; } = 30;

    public int Digits { get; set; } = 6;

    public int AllowedClockSkewSteps { get; set; } = 1;

    public int MaxFailedAttempts { get; set; } = 5;

    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(5);

    public int RecoveryCodeCount { get; set; } = 10;
}
