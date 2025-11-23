using Plugin.UplayServer.Quazal.Enums;
using ServerShared.IO;

namespace Plugin.UplayServer.Quazal.Serializables;

public struct PrudpPacketV0() : ICustomSerializable
{
    public VirtualPort Source = new();
    public VirtualPort Destination = new();
    public PacketType PacketType;
    public PacketFlags Flags;
    public byte SessionId;
    public uint Signature;
    public ushort SequenceId;

    // Packet Type Specific data
    public uint ConnectionSignature;
    public byte FragmentId;

    public ushort PayloadSize;
    public byte[] Payload = [];

    public byte Checksum;

    public bool UseCompression;

    public void Deserialize(EndiannessReader reader)
    {
        Source = reader.ReadSerializable<VirtualPort>();
        Destination = reader.ReadSerializable<VirtualPort>();
        var flags = reader.ReadByte();
        PacketType = (PacketType)(flags & 0x7);
        Flags = (PacketFlags)(flags >> 3);
        SessionId = reader.ReadByte();
        Signature = reader.ReadUInt32();
        SequenceId = reader.ReadUInt16();

        if (PacketType is PacketType.Syn or PacketType.Connect)
            ConnectionSignature = reader.ReadUInt32();

        if (PacketType is PacketType.Data)
            FragmentId = reader.ReadByte();

        if (Flags.HasFlag(PacketFlags.HasSize))
            PayloadSize = reader.ReadUInt16();
        else
            PayloadSize = (ushort)(reader.BaseStream.Length - reader.BaseStream.Position - 1);

        Payload = reader.ReadBytes(PayloadSize);
        Checksum = reader.ReadByte();
    }

    public void Serialize(EndiannessWriter writer)
    {

    }

    public readonly override string ToString()
    {
        return $"S:{Source} D: {Destination} T:{PacketType} F: {Flags} ({(byte)Flags}) SID: {SessionId} SIG: {Signature} SEQID: {SequenceId} " +
                $"CSIG: {ConnectionSignature}, FID: {FragmentId} PSize: {PayloadSize} C: {Checksum} (COMP:{UseCompression})";
    }
}
