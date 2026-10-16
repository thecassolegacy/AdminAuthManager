namespace AdminAuth.Authentication;

public sealed record GeneratedApiKey(string PlainTextKey, string Prefix, string KeyHash);
