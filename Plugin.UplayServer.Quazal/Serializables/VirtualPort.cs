using Plugin.UplayServer.Quazal.Enums;
using ServerShared.IO;

namespace Plugin.UplayServer.Quazal.Serializables;

public struct VirtualPort : ICustomSerializable
{
    public StreamType StreamType;
    public byte Port;

    public void Deserialize(EndiannessReader reader)
    {
        byte data = reader.ReadByte();
        StreamType = (StreamType)(data >> 4);
        Port = (byte)(data & 0xF);
    }

    public readonly void Serialize(EndiannessWriter writer)
    {
        byte data = Port;
        data |= (byte)((byte)StreamType << 4);
        writer.Write(data);
    }

    public readonly override string ToString()
    {
        return $"({StreamType} {Port})";
    }
}
