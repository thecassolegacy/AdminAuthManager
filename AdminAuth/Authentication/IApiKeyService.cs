namespace AdminAuth.Authentication;

public interface IApiKeyService
{
    GeneratedApiKey Generate();

    bool TryParse(string apiKey, out string prefix, out string secret);

    string ComputeHash(string secret);

    bool Verify(string secret, string expectedHash);
}
