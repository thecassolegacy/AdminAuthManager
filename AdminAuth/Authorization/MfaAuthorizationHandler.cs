using AdminAuth.Authentication;
using Microsoft.AspNetCore.Authorization;

namespace AdminAuth.Authorization;

public sealed class MfaAuthorizationHandler : AuthorizationHandler<MfaRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        MfaRequirement requirement)
    {
        var isApiKeyCaller = context.User.Identities.Any(identity =>
            identity.IsAuthenticated
            && identity.AuthenticationType == ApiKeyAuthenticationDefaults.AuthenticationScheme);

        if (isApiKeyCaller || context.User.HasClaim(AdminAuthClaimTypes.Mfa, bool.TrueString))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
