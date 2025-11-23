namespace Plugin.UplayServer.Quazal.Enums;

public enum PacketType : byte
{
    Syn,
    Connect,
    Data,
    Disconnect,
    Ping,
    User,
    Route,
    Raw,
}
