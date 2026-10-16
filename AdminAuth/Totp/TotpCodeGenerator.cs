using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace AdminAuth.Totp;

internal static class TotpCodeGenerator
{
    public static string GenerateCode(ReadOnlySpan<byte> secret, long timeStep, int digits)
    {
        Span<byte> counter = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(counter, timeStep);

        using var hmac = new HMACSHA1(secret.ToArray());
        var hash = hmac.ComputeHash(counter.ToArray());
        var offset = hash[^1] & 0x0F;
        var binaryCode = ((hash[offset] & 0x7F) << 24)
            | (hash[offset + 1] << 16)
            | (hash[offset + 2] << 8)
            | hash[offset + 3];

        return (binaryCode % (int)Math.Pow(10, digits)).ToString($"D{digits}");
    }

    public static bool Matches(string expectedCode, string code)
    {
        if (code.Length != expectedCode.Length || code.Any(character => !char.IsAsciiDigit(character)))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expectedCode),
            Encoding.UTF8.GetBytes(code));
    }
}
