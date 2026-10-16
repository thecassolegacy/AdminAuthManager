using System.Text;

namespace AdminAuth.Totp;

internal static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return string.Empty;
        }

        var output = new StringBuilder((data.Length * 8 + 4) / 5);
        var buffer = 0;
        var bitsInBuffer = 0;

        foreach (var value in data)
        {
            buffer = (buffer << 8) | value;
            bitsInBuffer += 8;

            while (bitsInBuffer >= 5)
            {
                output.Append(Alphabet[(buffer >> (bitsInBuffer - 5)) & 31]);
                bitsInBuffer -= 5;
            }
        }

        if (bitsInBuffer > 0)
        {
            output.Append(Alphabet[(buffer << (5 - bitsInBuffer)) & 31]);
        }

        return output.ToString();
    }

    public static byte[] Decode(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        var buffer = 0;
        var bitsInBuffer = 0;
        var output = new List<byte>(value.Length * 5 / 8);

        foreach (var character in value)
        {
            if (char.IsWhiteSpace(character) || character == '-')
            {
                continue;
            }

            var index = Alphabet.IndexOf(char.ToUpperInvariant(character));
            if (index < 0)
            {
                throw new FormatException("The value is not valid Base32.");
            }

            buffer = (buffer << 5) | index;
            bitsInBuffer += 5;

            while (bitsInBuffer >= 8)
            {
                output.Add((byte)(buffer >> (bitsInBuffer - 8)));
                bitsInBuffer -= 8;
            }
        }

        return output.ToArray();
    }
}
