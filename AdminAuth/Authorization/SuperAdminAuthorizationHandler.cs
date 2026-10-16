using Microsoft.AspNetCore.Authorization;

namespace AdminAuth.Authorization;

public sealed class SuperAdminAuthorizationHandler : AuthorizationHandler<SuperAdminRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        SuperAdminRequirement requirement)
    {
        if (context.User.HasClaim(AdminAuthClaimTypes.SuperAdmin, bool.TrueString))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
