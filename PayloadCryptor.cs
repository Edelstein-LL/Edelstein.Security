using CommunityToolkit.HighPerformance;

using System.Security.Cryptography;
using System.Text;

namespace Edelstein.Security;

public static class PayloadCryptor
{
    private const string AesKey = "3559b435f24b297a79c68b9709ef2125";
    private static readonly byte[] AesKeyBytes = Encoding.UTF8.GetBytes(AesKey);

    public static string Decrypt(string encryptedData)
    {
        byte[] encryptedDataBytes = Convert.FromBase64String(encryptedData);

        using Aes aes = Aes.Create();

        byte[] iv = encryptedDataBytes[..16];

        using ICryptoTransform decryptor = aes.CreateDecryptor(AesKeyBytes, iv);

        using CryptoStream cryptoStream = new(encryptedDataBytes.AsMemory(16).AsStream(), decryptor, CryptoStreamMode.Read);
        using MemoryStream decryptedDataStream = new();

        cryptoStream.CopyTo(decryptedDataStream);

        return Encoding.UTF8.GetString(decryptedDataStream.ToArray());
    }

    public static string Encrypt(string data)
    {
        byte[] dataBytes = Encoding.UTF8.GetBytes(data);

        using Aes aes = Aes.Create();
        aes.GenerateIV();

        using ICryptoTransform encryptor = aes.CreateEncryptor(AesKeyBytes, aes.IV);

        using MemoryStream encryptedDataStream = new();
        using CryptoStream cryptoStream = new(encryptedDataStream, encryptor, CryptoStreamMode.Write);

        aes.IV.AsMemory().AsStream().CopyTo(encryptedDataStream);
        dataBytes.AsMemory().AsStream().CopyTo(cryptoStream);

        cryptoStream.FlushFinalBlock();

        return Convert.ToBase64String(encryptedDataStream.ToArray());
    }

    public static async Task Encrypt(Stream inputStream, Stream outputStream)
    {
        using Aes aes = Aes.Create();
        aes.GenerateIV();

        using ICryptoTransform encryptor = aes.CreateEncryptor(AesKeyBytes, aes.IV);
        await using CryptoStream base64Stream = new(outputStream, new ToBase64Transform(), CryptoStreamMode.Write);
        await using CryptoStream cryptoStream = new(base64Stream, encryptor, CryptoStreamMode.Write);

        await base64Stream.WriteAsync(aes.IV.AsMemory()).ConfigureAwait(false);

        await inputStream.CopyToAsync(cryptoStream).ConfigureAwait(false);

        await cryptoStream.FlushFinalBlockAsync().ConfigureAwait(false);
    }
}
