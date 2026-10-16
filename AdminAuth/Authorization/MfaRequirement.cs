using Microsoft.AspNetCore.Authorization;

namespace AdminAuth.Authorization;

/// <summary>
/// Requires a JWT principal to carry the MFA claim. API-key callers are exempt because they never use TOTP.
/// </summary>
public sealed class MfaRequirement : IAuthorizationRequirement
{
}
