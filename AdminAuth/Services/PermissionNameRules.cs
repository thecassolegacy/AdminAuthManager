using System.Text.RegularExpressions;

namespace AdminAuth.Services;

/// <summary>
/// Validation for permission names: 1 to 128 characters of letters, digits, '.', '_', ':' and '-', starting with a letter or digit.
/// </summary>
public static class PermissionNameRules
{
    public const int MaxLength = 128;

    private static readonly Regex NamePattern = new(
        @"\A[A-Za-z0-9][A-Za-z0-9._:\-]*\z",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static string Validate(string name, string parameterName = "name")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name, parameterName);

        var trimmed = name.Trim();

        if (trimmed.Length > MaxLength || !NamePattern.IsMatch(trimmed))
        {
            throw new ArgumentException(
                $"Permission names must be 1 to {MaxLength} characters of letters, digits, '.', '_', ':' or '-', starting with a letter or digit.",
                parameterName);
        }

        return trimmed;
    }
}
