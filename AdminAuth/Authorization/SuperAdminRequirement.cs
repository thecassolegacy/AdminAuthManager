using Microsoft.AspNetCore.Authorization;

namespace AdminAuth.Authorization;

public sealed class SuperAdminRequirement : IAuthorizationRequirement
{
}
