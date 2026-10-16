using System.Security.Cryptography;
using System.Text;
using AdminAuth.Configuration;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace AdminAuth.Authentication;

public sealed class ApiKeyService(IOptions<AdminAuthOptions> options) : IApiKeyService
{
    public const int MaxKeyLength = 128;

    private const int PrefixBytes = 8;
    private const int SecretBytes = 32;
    private const char Separator = '.';

    public GeneratedApiKey Generate()
    {
        var prefix = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(PrefixBytes));
        var secret = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(SecretBytes));

        return new GeneratedApiKey($"{prefix}{Separator}{secret}", prefix, ComputeHash(secret));
    }

    public bool TryParse(string apiKey, out string prefix, out string secret)
    {
        prefix = string.Empty;
        secret = string.Empty;

        if (string.IsNullOrWhiteSpace(apiKey) || apiKey.Length > MaxKeyLength)
        {
            return false;
        }

        var separatorIndex = apiKey.IndexOf(Separator);
        if (separatorIndex <= 0 || separatorIndex == apiKey.Length - 1 || apiKey.IndexOf(Separator, separatorIndex + 1) >= 0)
        {
            return false;
        }

        prefix = apiKey[..separatorIndex];
        secret = apiKey[(separatorIndex + 1)..];
        return prefix.Length <= 16;
    }

    public string ComputeHash(string secret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);

        var pepper = Encoding.UTF8.GetBytes(options.Value.ApiKeyPepper);
        return Convert.ToHexString(HMACSHA256.HashData(pepper, Encoding.UTF8.GetBytes(secret)));
    }

    public bool Verify(string secret, string expectedHash)
    {
        if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(expectedHash))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(ComputeHash(secret)),
            Encoding.UTF8.GetBytes(expectedHash));
    }
}
