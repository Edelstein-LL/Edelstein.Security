using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Edelstein.Security;

public static partial class OAuth
{
    private const string Version = "1.0";
    private const string HmacSignatureMethod = "HMAC-SHA1";
    private const string RsaSignatureMethod = "RSA-SHA1";
    private const string ConsumerKey = "232610769078541";

    private const string SecretHmacKey = "d8f68e284efdf60bbaec2d225c0cfd42";

    private const int TimeoutSeconds = 30;

    [GeneratedRegex("(.+)=\"(.+)\"")]
    private static partial Regex OAuthHeaderValueRegex();

    public static string BuildStringToSign(string httpMethod, string url, Dictionary<string, string> oauthValues)
    {
        Uri typedUri = new(url);

        List<string> encodedValues = [];

        foreach (KeyValuePair<string, string> oauthValuePair in oauthValues.OrderBy(x => x.Key))
        {
            if (oauthValuePair.Key == "oauth_signature")
                continue;

            encodedValues.Add($"{Uri.EscapeDataString(oauthValuePair.Key)}={Uri.EscapeDataString(oauthValuePair.Value)}");
        }

        string encodedOauthValues = String.Join("&", encodedValues);

        return String.Join("&", new List<string>
        {
            httpMethod,
            typedUri.GetLeftPart(UriPartial.Path),
            encodedOauthValues
        }.Select(Uri.EscapeDataString));
    }

    public static string Sign(string httpMethod, string url, Dictionary<string, string> oauthValues)
    {
        string stringToSign = BuildStringToSign(httpMethod, url, oauthValues);
        return Convert.ToBase64String(HmacSigner.SignData(stringToSign, SecretHmacKey));
    }

    public static string BuildResponseOAuthHeader(string httpMethod, string url, string bodyHash)
    {
        Dictionary<string, string> oauthValues = new()
        {
            ["oauth_body_hash"] = bodyHash,
            ["oauth_consumer_key"] = ConsumerKey,
            ["oauth_nonce"] = Guid.NewGuid().ToString().Replace("-", ""),
            ["oauth_signature_method"] = "HMAC-SHA1",
            ["oauth_timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
            ["oauth_version"] = "1.0"
        };

        Uri typedUri = new(url);
        string query = typedUri.Query.Length > 0 ? typedUri.Query[1..] : "";
        foreach (string queryItems in query.Split("&", StringSplitOptions.RemoveEmptyEntries))
        {
            string[] keyValuePair = queryItems.Split("=");

            oauthValues.Add(keyValuePair[0], keyValuePair.Length == 1 ? "" : keyValuePair[1]);
        }

        oauthValues["oauth_signature"] =
            Sign(httpMethod, typedUri.GetLeftPart(UriPartial.Path), oauthValues.OrderBy(x => x.Key).ToDictionary());

        return BuildOAuthHeaderFromValues(oauthValues);
    }

    public static string BuildOAuthHeaderFromValues(Dictionary<string, string> oauthValues) =>
        "OAuth " + String.Join(",", oauthValues.OrderBy(x => x.Key).Select(x => $"{x.Key}=\"{Uri.EscapeDataString(x.Value)}\""));

    public static Dictionary<string, string> BuildOAuthValuesFromHeader(string header)
    {
        header = header[6..];

        Dictionary<string, string> values = new();

        foreach (string headerPart in header.Split(","))
        {
            Match match = OAuthHeaderValueRegex().Match(headerPart);
            if (!match.Success)
                continue;

            values.TryAdd(match.Groups[1].Value, Uri.UnescapeDataString(match.Groups[2].Value));
        }

        return values;
    }

    // ReSharper disable once InconsistentNaming
    public static bool TryGetUserIdFromRequestorId(string xoauthRequestorId, [NotNullWhen(true)] out string? userId)
    {
        userId = null;

        if (!xoauthRequestorId.StartsWith(ConsumerKey))
            return false;

        userId = xoauthRequestorId[ConsumerKey.Length..];

        return true;
    }

    public static bool TryGetUserIdFromOAuthHeader(string oauthHeader, [NotNullWhen(true)] out string? userId)
    {
        userId = null;

        Dictionary<string, string> oauthValues = BuildOAuthValuesFromHeader(oauthHeader);

        string xoauthRequestorId = oauthValues["xoauth_requestor_id"];

        return TryGetUserIdFromRequestorId(xoauthRequestorId, out userId);
    }

    public static bool VerifyOAuthHmac(string httpMethod, string url, string body, Dictionary<string, string> oauthValues,
        bool ignoreTimestamp = false)
    {
        if (!oauthValues.TryGetValue("oauth_version", out string? oauthVersion) ||
            oauthVersion != Version)
            return false;

        if (!oauthValues.TryGetValue("oauth_signature_method", out string? oauthSignatureMethod) ||
            oauthSignatureMethod != HmacSignatureMethod)
            return false;

        // TODO: Check if nonce is not reused (is actually needed?)
        //if (!oauthValues.TryGetValue("oauth_nonce", out string? oauthNonce) ||
        //    NONCE IS NOT UNIQUE)
        //    return false;

        string actualBodyHash = Convert.ToBase64String(SHA1.HashData(Encoding.UTF8.GetBytes(body)));

        if (!oauthValues.TryGetValue("oauth_body_hash", out string? oauthBodyHash) ||
            oauthBodyHash != actualBodyHash)
            return false;

        if (!oauthValues.TryGetValue("oauth_consumer_key", out string? oauthConsumerKey) ||
            oauthConsumerKey != ConsumerKey)
            return false;

        DateTimeOffset now = DateTimeOffset.UtcNow;

        if (!oauthValues.TryGetValue("oauth_timestamp", out string? oauthTimestamp))
            return false;

        if (!ignoreTimestamp && (!Int64.TryParse(oauthTimestamp, out long oauthTimestampLong) ||
            oauthTimestampLong > (now + TimeSpan.FromSeconds(TimeoutSeconds)).ToUnixTimeSeconds() ||
            oauthTimestampLong < (now - TimeSpan.FromSeconds(TimeoutSeconds)).ToUnixTimeSeconds()))
            return false;

        if (!oauthValues.TryGetValue("oauth_signature", out string? oauthSignature))
            return false;

        string actualSignature =
            Convert.ToBase64String(HmacSigner.SignData(BuildStringToSign(httpMethod, url, oauthValues), SecretHmacKey));

        if (oauthSignature != actualSignature)
            return false;

        return true;
    }

    public static bool VerifyOAuthRsa(string httpMethod, string url, string body, Dictionary<string, string> oauthValues, string publicKey,
        bool ignoreTimestamp = false)
    {
        if (!oauthValues.TryGetValue("oauth_version", out string? oauthVersion) ||
            oauthVersion != Version)
            return false;

        if (!oauthValues.TryGetValue("oauth_signature_method", out string? oauthSignatureMethod) ||
            oauthSignatureMethod != RsaSignatureMethod)
            return false;

        // TODO: Check if nonce is not reused (is actually needed?)
        //if (!oauthValues.TryGetValue("oauth_nonce", out string? oauthNonce) ||
        //    NONCE IS NOT UNIQUE)
        //    return false;

        string actualBodyHash = Convert.ToBase64String(SHA1.HashData(Encoding.UTF8.GetBytes(body)));

        if (!oauthValues.TryGetValue("oauth_body_hash", out string? oauthBodyHash) ||
            oauthBodyHash != actualBodyHash)
            return false;

        if (!oauthValues.TryGetValue("oauth_consumer_key", out string? oauthConsumerKey) ||
            oauthConsumerKey != ConsumerKey)
            return false;

        DateTimeOffset now = DateTimeOffset.UtcNow;

        if (!oauthValues.TryGetValue("oauth_timestamp", out string? oauthTimestamp))
            return false;

        if (!ignoreTimestamp && (!Int64.TryParse(oauthTimestamp, out long oauthTimestampLong) ||
            oauthTimestampLong > (now + TimeSpan.FromSeconds(TimeoutSeconds)).ToUnixTimeSeconds() ||
            oauthTimestampLong < (now - TimeSpan.FromSeconds(TimeoutSeconds)).ToUnixTimeSeconds()))
            return false;

        if (!oauthValues.TryGetValue("oauth_signature", out string? oauthSignature))
            return false;

        byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
        byte[] oauthSignatureBytes = Convert.FromBase64String(oauthSignature);

        if (!RsaSigner.VerifySignature(BuildStringToSign(httpMethod, url, oauthValues), oauthSignatureBytes, publicKeyBytes))
            return false;

        // xoauth_requestor_id should be verified here, because public key depends on it's user id

        if (!oauthValues.TryGetValue("xoauth_as_hash", out string? xoauthAsHash))
            return false;

        byte[] xoauthAsHashBytes = Convert.FromBase64String(xoauthAsHash);

        if (!RsaSigner.VerifySignature($"{SecretHmacKey}{oauthTimestamp}", xoauthAsHashBytes, publicKeyBytes))
            return false;

        return true;
    }
}
