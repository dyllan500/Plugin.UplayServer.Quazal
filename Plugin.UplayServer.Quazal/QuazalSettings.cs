namespace Plugin.UplayServer.Quazal;

/// <summary>Local RendezVous listener settings shared by every title.</summary>
public sealed class QuazalSettings
{
    /// <summary>
    /// UDP listeners accepted by this plugin. Each title's REST
    /// rendezvous_configuration.json advertises one of these endpoints adding
    /// a game is a configuration change, not a protocol-plugin fork.
    /// </summary>
    public int[] Ports { get; set; } = [6570];

    /// <summary>
    /// Sends the transport-level SYN/CONNECT/PING/DATA acknowledgements. This
    /// intentionally stops before encrypted LoginProtocol/RMC handling.
    /// </summary>
    public bool EnableTransportAcks { get; set; } = true;

    /// <summary>
    /// Experimental generic secure-connect probe. On CONNECT, include a
    /// freshly generated P-256 ECK1 public blob in the PRUDP ACK. This
    /// advances CNG-backed clients to their key-import/validation path without
    /// pretending that LoginProtocol/RMC is implemented.
    /// </summary>
    public bool SendSecureConnectProbe { get; set; }

    /// <summary>
    /// Reply to an ECK1 CONNECT with the authenticated P-256 envelope,
    /// when <see cref="RendezVousIdentityFile"/> supplies the same identity
    /// which REST advertised to the game.
    /// </summary>
    public bool EnableAuthenticatedSecureConnect { get; set; } = true;

    /// <summary>
    /// Optional shared REST/Quazal identity document. When configured, Quazal
    /// loads the ECDSA P-256 private key whose ECS1 public half REST
    /// advertises for opted-in titles. The secure CONNECT envelope is not
    /// emitted until its authenticated layout is known.
    /// </summary>
    public string? RendezVousIdentityFile { get; set; }

    /// <summary>Bound the in-memory peer table while a client retries.</summary>
    public int MaxPeers { get; set; } = 8;

    /// <summary>
    /// Address embedded in named-RMC responses that hand the client a follow-up
    /// server to connect to (e.g. LoginWithToken_V1's and Register_V1's result
    /// both end in a prudp:/address=...;port=... URL
    /// </summary>
    public string PublicHost { get; set; } = "127.0.0.1";
}
