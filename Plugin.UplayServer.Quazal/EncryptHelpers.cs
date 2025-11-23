namespace Plugin.UplayServer.Quazal;

public static class EncryptHelpers
{
    public static byte[] Encrypt(byte[] key, byte[] data)
        => [.. EncryptOutput(key, data)];

    public static byte[] EncryptInitalize(byte[] key)
    {
        byte[] s = [.. Enumerable.Range(0, 256).Select(i => (byte)i)];
        for (int i = 0, j = 0; i < 256; i++)
        {
            j = (j + key[i % key.Length] + s[i]) & 255;

            (s[j], s[i]) = (s[i], s[j]);
        }
        return s;
    }

    public static IEnumerable<byte> EncryptOutput(byte[] key, IEnumerable<byte> data)
    {
        byte[] s = EncryptInitalize(key);
        int i = 0;
        int j = 0;
        return data.Select((b) =>
        {
            i = (i + 1) & 255;
            j = (j + s[i]) & 255;
            (s[j], s[i]) = (s[i], s[j]);
            return (byte)(b ^ s[(s[i] + s[j]) & 255]);
        });
    }
}
