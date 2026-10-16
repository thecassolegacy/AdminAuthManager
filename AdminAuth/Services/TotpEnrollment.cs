namespace AdminAuth.Services;

public sealed record TotpEnrollment(string Secret, string ProvisioningUri);
