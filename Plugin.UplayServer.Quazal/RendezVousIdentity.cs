using System.Security.Cryptography;
using System.Text.Json;

namespace Plugin.UplayServer.Quazal;

/// <summary>
/// Private half of the server identity shared with the REST plugin. The JSON
/// document contains a base64 PKCS#8 P-256 ECDSA private key under
/// <c>EcdsaP256PrivateKeyPkcs8</c>.
/// </summary>
internal static class RendezVousIdentity
{
    public static ECDsa? Load(string? configuredPath)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
            return null;

        try
        {
            string path = Path.IsPathFullyQualified(configuredPath)
                ? configuredPath
                : Path.Combine(Directory.GetCurrentDirectory(), configuredPath);
            using JsonDocument document = JsonDocument.Parse(File.ReadAllText(path));
            if (!document.RootElement.TryGetProperty("EcdsaP256PrivateKeyPkcs8", out JsonElement value) ||
                value.GetString() is not string encoded || string.IsNullOrWhiteSpace(encoded))
            {
                Log.Error("[quazal] RendezVous identity {Path} has no EcdsaP256PrivateKeyPkcs8 value", path);
                return null;
            }

            byte[] privateKey = Convert.FromBase64String(encoded);
            ECDsa signer = ECDsa.Create();
            signer.ImportPkcs8PrivateKey(privateKey, out int consumed);
            if (consumed != privateKey.Length)
                throw new CryptographicException("PKCS#8 identity contains trailing bytes");

            ECParameters parameters = signer.ExportParameters(includePrivateParameters: false);
            if (parameters.Q.X is not { Length: 32 } || parameters.Q.Y is not { Length: 32 })
                throw new CryptographicException("RendezVous identity is not P-256");

            return signer;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or FormatException or CryptographicException or JsonException)
        {
            Log.Error("[quazal] cannot load RendezVous identity {Path}: {Error}", configuredPath, exception.Message);
            return null;
        }
    }
}
