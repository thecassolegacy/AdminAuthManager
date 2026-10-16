namespace AdminAuth.Authorization;

public static class AdminAuthClaimTypes
{
    public const string Permission = "admin_permission";

    public const string SuperAdmin = "admin_super_admin";

    /// <summary>Set to "True" by the token issuer after the administrator completed a second factor.</summary>
    public const string Mfa = "admin_mfa";
}
