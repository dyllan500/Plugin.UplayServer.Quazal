using ModdableWebServer.Interfaces;
using ServerShared.Controllers;
using ServerShared.EventArguments;
using ServerShared.Plugins;
using ServerShared.Server;
using System.Net;
using Plugin.UplayServer.Quazal.Serializables;

namespace Plugin.UplayServer.Quazal;

/// <summary>Attaches the shared RendezVous/PRUDP responder to ServerApp UDP ports.</summary>
public sealed class UplayQuazalPlugin : ServerPlugin<QuazalSettings>
{
    public override uint Priority => 1;
    public override string Name => "UplayServer.Quazal";

    private QuazalResponder? _responder;

    public override void Start()
    {
        int[] missing = Config.Ports
            .Where(port => !ServerController.Servers.Any(s => s.Port == port && s.IsUdp))
            .ToArray();
        if (missing.Length > 0)
        {
            Log.Error("[quazal] no UDP server registered for port(s) {Ports} — add them to ServerAppSettings.json with UseUDP=true",
                string.Join(", ", missing));
            return;
        }

        _responder = new QuazalResponder(Config);
        CoreUdpSession.OnBytesReceived += OnUdpBytes;
        Log.Information("[quazal] PRUDP V0 listener attached on UDP {Ports}; transport ACKs={Acks}; authenticated secure CONNECT={SecureConnect}; signing identity={Identity}",
            string.Join("/", Config.Ports), Config.EnableTransportAcks, Config.EnableAuthenticatedSecureConnect,
            _responder.HasSigningIdentity ? "loaded" : "not configured");
    }

    public override void Stop()
    {
        CoreUdpSession.OnBytesReceived -= OnUdpBytes;
        _responder?.Dispose();
        _responder = null;
    }

    private void OnUdpBytes(object? sender, SessionBytesReceivedEventArgs e)
    {
        if (_responder is null || sender is not CoreUdpSession session ||
            !Config.Ports.Contains(session.Server.Port) || session.EndPoint is not IPEndPoint source)
            return;

        if (!PrudpPacketV0.TryDeserialize(e.Data.Span, out PrudpPacketV0 packet))
        {
            Log.Debug("[quazal] ignored {Length}-byte non-V0 datagram from {Source}", e.Data.Length, source);
            return;
        }

        Log.Information("[quazal] {Source} {Packet}", source, packet);
        try
        {
            IReadOnlyList<byte[]> replies = _responder.Handle(packet, source);
            foreach (byte[] reply in replies)
            {
                session.SendAsync(reply);
                Log.Debug("[quazal] ACK {Type} seq={Sequence} -> {Source} ({Length} bytes) wire={Wire}",
                    packet.PacketType, packet.SequenceId, source, reply.Length,
                    Convert.ToHexString(reply));
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "[quazal] handler failed for {Source}; keeping UDP listener alive", source);
        }
    }
}
