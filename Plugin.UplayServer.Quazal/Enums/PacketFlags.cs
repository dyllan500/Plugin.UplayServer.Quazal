namespace Plugin.UplayServer.Quazal.Enums;

[Flags]
public enum PacketFlags : byte
{
    None,
    Ack = 1,
    Reliable = 2,
    NeedAck = 4,
    Unknown = 8,
    HasSize = 16,
}
