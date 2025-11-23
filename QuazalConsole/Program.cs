using Ionic.Zlib;
using Plugin.UplayServer.Quazal;
using Plugin.UplayServer.Quazal.Serializables;
using ServerShared.IO;

namespace QuazalConsole;

internal class Program
{
    static void Main(string[] args)
    {

        byte[] key = Convert.FromHexString("4344264D5D4C43453748585A3B271B2E");
        key = Convert.FromHexString("4344264D4C"); //CD&ML
        Console.WriteLine("Hello, World!");
        PrudpPacketV0 packet = new();
        if (!File.Exists("input.txt"))
            return;
        var bin = Convert.FromHexString(File.ReadAllBytes("input.txt"));
        MemoryStream ms = new(bin);
        EndiannessReader reader = new(ms, Endianness.Little);
        packet.Deserialize(reader);
        Console.WriteLine(packet.ToString());

        Console.WriteLine(Convert.ToHexString(packet.Payload));

        if (packet.Payload.Length != 0 &&
            packet.PacketType is not Plugin.UplayServer.Quazal.Enums.PacketType.Syn && 
            packet.Source.StreamType != Plugin.UplayServer.Quazal.Enums.StreamType.NAT)
        {
            if (packet.Source.StreamType == Plugin.UplayServer.Quazal.Enums.StreamType.OldRVSecure)
            {
                packet.Payload = EncryptHelpers.Encrypt(key, packet.Payload);
            }
            packet.UseCompression = packet.Payload[0] != 0;
            Console.WriteLine(Convert.ToHexString(packet.Payload));
            if (packet.UseCompression)
            {
                MemoryStream payload_result = new();
                ZlibStream stream = new(new MemoryStream(packet.Payload[1..]), CompressionMode.Decompress);
                stream.CopyTo(payload_result);
                packet.Payload = payload_result.ToArray();
            }
            else
                packet.Payload = packet.Payload[1..];
            packet.PayloadSize = (ushort)packet.Payload.Length;
        }
        Console.WriteLine(Convert.ToHexString(packet.Payload));
        Console.WriteLine(packet.ToString());
    }
}
