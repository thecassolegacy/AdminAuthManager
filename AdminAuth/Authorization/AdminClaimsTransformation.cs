using System.Security.Claims;
using AdminAuth.Authentication;
using AdminAuth.Persistence;
using Microsoft.AspNetCore.Authentication;

namespace AdminAuth.Authorization;

/// <summary>
/// Replaces token-supplied permission and super-admin claims with values from the store, and rejects
/// tokens whose subject is unknown or inactive.
/// </summary>
public sealed class AdminClaimsTransformation(IAdminUserStore userStore) : IClaimsTransformation
{
    private const string RevalidatedClaimType = "admin_revalidated";

    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var target = principal.Identities.FirstOrDefault(identity =>
            identity.IsAuthenticated
            && identity.AuthenticationType != ApiKeyAuthenticationDefaults.AuthenticationScheme
            && !identity.HasClaim(claim => claim.Type == RevalidatedClaimType));

        if (target is null)
        {
            return principal;
        }

        var subject = target.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? target.FindFirst("sub")?.Value;
        var user = Guid.TryParse(subject, out var administratorId)
            ? await userStore.FindAdministratorAsync(administratorId)
            : null;

        var replacement = user is { IsActive: true }
            ? Rebuild(target, user)
            : new ClaimsIdentity();

        var result = new ClaimsPrincipal();
        foreach (var identity in principal.Identities)
        {
            result.AddIdentity(ReferenceEquals(identity, target) ? replacement : identity);
        }

        return result;
    }

    private static ClaimsIdentity Rebuild(ClaimsIdentity source, Entities.AdminUser user)
    {
        var claims = source.Claims
            .Where(claim => claim.Type is not (AdminAuthClaimTypes.Permission or AdminAuthClaimTypes.SuperAdmin))
            .ToList();

        claims.Add(new Claim(RevalidatedClaimType, bool.TrueString));

        if (user.IsSuperAdmin)
        {
            claims.Add(new Claim(AdminAuthClaimTypes.SuperAdmin, bool.TrueString));
        }

        claims.AddRange(user.Permissions.Select(permission =>
            new Claim(AdminAuthClaimTypes.Permission, permission.AdminPermission.Name)));

        return new ClaimsIdentity(claims, source.AuthenticationType, source.NameClaimType, source.RoleClaimType);
    }
}
