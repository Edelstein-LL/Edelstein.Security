using System.Security.Cryptography;
using System.Text;

namespace Edelstein.Security;

public static class HmacSigner
{
    public static byte[] SignData(string data, string secretKey)
    {
        byte[] secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);
        byte[] dataBytes = Encoding.UTF8.GetBytes(data);

        using HMACSHA1 hmacsha1 = new(secretKeyBytes);

        return hmacsha1.ComputeHash(dataBytes);
    }
}
