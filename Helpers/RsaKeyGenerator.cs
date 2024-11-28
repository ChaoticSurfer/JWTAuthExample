using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace JwtRoleAuthentication.Helpers;

public static class RsaKeyGenerator
{
    public static RsaSecurityKey GenerateOrLoadKeys()
    {
        var rsa = RSA.Create();
        if (!File.Exists("private_key.xml"))
        {
            File.WriteAllText("private_key.xml", rsa.ToXmlString(true));
            File.WriteAllText("public_key.xml", rsa.ToXmlString(false));
        }
        rsa.FromXmlString(File.ReadAllText("private_key.xml"));
        return new RsaSecurityKey(rsa);
    }

    public static RsaSecurityKey LoadPublicKey()
    {
        var rsa = RSA.Create();
        rsa.FromXmlString(File.ReadAllText("public_key.xml"));
        return new RsaSecurityKey(rsa);
    }
}