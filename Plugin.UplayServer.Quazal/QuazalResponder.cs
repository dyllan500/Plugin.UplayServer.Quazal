using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Plugin.UplayServer.Quazal.Enums;
using Plugin.UplayServer.Quazal.Serializables;
using System.Net;

namespace Plugin.UplayServer.Quazal;

/// <summary>
/// The transport boundary for a legacy Quazal listener. It establishes only the
/// PRUDP envelope encrypted RMC login 
/// </summary>
internal sealed class QuazalResponder(QuazalSettings settings) : IDisposable
{
    private sealed class Peer
    {
        public required uint ServerSignature { get; set; }
        public required byte ServerSessionId { get; set; }
        public uint ClientSignature { get; set; }
        public byte AccessKeyChecksum { get; set; }
        public bool SynAcknowledged { get; set; }
        public bool Connected { get; set; }
        public ECDiffieHellman? SecureAgreement { get; set; }
        public byte[]? SecureSessionKey { get; set; }
        public byte[]? SecureConnectSignature { get; set; }
        public byte[]? SecureConnectExtension { get; set; }
        public byte[]? LastClientEcdhBlob { get; set; }
        public ushort ServerSequenceId { get; set; } = 1;
        public ushort RmcResponseCounter { get; set; }
    }

    private readonly ConcurrentDictionary<IPEndPoint, Peer> _peers = [];

    private readonly ECDsa? _signingIdentity = RendezVousIdentity.Load(settings.RendezVousIdentityFile);

    public bool HasSigningIdentity => _signingIdentity is not null;

    public IReadOnlyList<byte[]> Handle(PrudpPacketV0 request, IPEndPoint source)
    {
        if (!settings.EnableTransportAcks)
            return [];

        bool needsAck = request.Flags.HasFlag(PacketFlags.NeedAck);

        if (request.PacketType == PacketType.Syn)
        {
            if (!needsAck)
                return [];
            if (_peers.Count >= settings.MaxPeers && !_peers.ContainsKey(source))
            {
                Log.Warning("[quazal] ignoring SYN from {Source}: peer limit {Limit}", source, settings.MaxPeers);
                return [];
            }
            Peer peer = _peers.GetOrAdd(source, _ => new()
            {
                ServerSignature = NewSignature(),
                ServerSessionId = NewSessionId(),
            });
            if (!peer.SynAcknowledged)
            {
                peer.ServerSignature = NewSignature();
                peer.ServerSessionId = NewSessionId();
                peer.ServerSequenceId = 1;
                peer.RmcResponseCounter = 0;
                ClearSecureState(peer);
            }
            LearnChecksumContribution(request, peer);
            peer.SynAcknowledged = true;
            return [SynAcknowledge(request, peer.ServerSignature).ToArray(peer.AccessKeyChecksum)];
        }

        if (!_peers.TryGetValue(source, out Peer? existing))
        {
            Log.Debug("[quazal] ignoring {Type} from {Source}: no SYN state", request.PacketType, source);
            return [];
        }

        LearnChecksumContribution(request, existing);

        if (request.PacketType == PacketType.Connect)
        {
            existing.ClientSignature = request.ConnectionSignature;
            existing.Connected = true;
            bool isFreshEcdhKey = IsP256EcdhBlob(request.Payload) &&
                !request.Payload.SequenceEqual(existing.LastClientEcdhBlob ?? []);
            if (settings.EnableAuthenticatedSecureConnect && _signingIdentity is not null && isFreshEcdhKey)
            {
                ClearSecureState(existing);
                existing.RmcResponseCounter = 0;
                existing.ServerSequenceId = 1;
                existing.LastClientEcdhBlob = request.Payload.ToArray();
                (existing.SecureConnectSignature, existing.SecureConnectExtension) =
                    CreateAuthenticatedSecureConnectEnvelope(existing, _signingIdentity);
                existing.SecureSessionKey = DeriveSecureSessionKey(existing.SecureAgreement!, request.Payload);
                Log.Information("[quazal] generated authenticated P-256 secure-CONNECT envelope for {Source}", source);
            }
            return needsAck ? [ConnectAcknowledge(request, existing).ToArray(existing.AccessKeyChecksum)] : [];
        }

        byte[]? loginResponse = null;
        if (request.PacketType == PacketType.Data && existing.SecureSessionKey is not null && request.Payload.Length > 0)
            loginResponse = HandleSecureLoginData(request, source, existing, settings);

        if (request.PacketType == PacketType.Disconnect)
        {
            existing.Connected = false;
            existing.SynAcknowledged = false;
            ClearSecureState(existing);
        }

        if (!needsAck)
            return loginResponse is null ? [] : [loginResponse];

        byte[] ack = Acknowledge(request, existing, existing.ClientSignature == 0 ? existing.ServerSignature : existing.ClientSignature)
            .ToArray(existing.AccessKeyChecksum);

        return loginResponse is null ? [ack] : [ack, loginResponse];
    }

    private static PrudpPacketV0 SynAcknowledge(PrudpPacketV0 request, uint serverSignature) => new()
    {
        Source = request.Destination,
        Destination = request.Source,
        PacketType = request.PacketType,
        Flags = PacketFlags.Ack,
        SessionId = request.SessionId,
        Signature = request.ConnectionSignature,
        SequenceId = request.SequenceId,
        ConnectionSignature = serverSignature,
        FragmentId = request.FragmentId,
        Payload = [],
        PayloadSize = 0,
        Checksum = 0,
    };

    private static PrudpPacketV0 ConnectAcknowledge(PrudpPacketV0 request, Peer peer) => new()
    {
        Source = request.Destination,
        Destination = request.Source,
        PacketType = PacketType.Connect,
        Flags = PacketFlags.Ack | PacketFlags.HasSize,
        SessionId = peer.ServerSessionId,
        Signature = peer.ClientSignature,
        SequenceId = request.SequenceId,
        ConnectionSignature = 0,
        Payload = peer.SecureConnectSignature ?? [],
        TrailingPayload = peer.SecureConnectExtension ?? [],
        PayloadSize = (ushort)(peer.SecureConnectSignature?.Length ?? 0),
        Checksum = 0,
    };

    /// <summary>
    /// Creates FC5's verified OldRVSecure CONNECT extension:
    /// ECDSA-P256(SHA-256(ECK1)) | u16(72) | ECK1 | random(32).
    /// </summary>
    private static (byte[] Signature, byte[] Extension) CreateAuthenticatedSecureConnectEnvelope(Peer peer,
                                                                                                    ECDsa signingIdentity)
    {
        peer.SecureAgreement = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = peer.SecureAgreement.ExportParameters(includePrivateParameters: false);
        if (parameters.Q.X is not { Length: 32 } x || parameters.Q.Y is not { Length: 32 } y)
            throw new CryptographicException("P-256 public coordinates were not 32 bytes");

        byte[] blob = new byte[8 + x.Length + y.Length];
        "ECK1"u8.CopyTo(blob);
        BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(4), 32);
        x.CopyTo(blob, 8);
        y.CopyTo(blob, 8 + x.Length);

        byte[] hash = SHA256.HashData(blob);
        byte[] signature = signingIdentity.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        if (signature.Length != 64)
            throw new CryptographicException($"P-256 secure-CONNECT signature has unexpected length {signature.Length}");

        byte[] extension = new byte[sizeof(ushort) + blob.Length + 32];
        BinaryPrimitives.WriteUInt16LittleEndian(extension, (ushort)blob.Length);
        blob.CopyTo(extension, sizeof(ushort));
        RandomNumberGenerator.Fill(extension.AsSpan(sizeof(ushort) + blob.Length));
        return (signature, extension);
    }

    private static bool IsP256EcdhBlob(ReadOnlySpan<byte> payload) =>
        payload.Length == 72 && payload[..4].SequenceEqual("ECK1"u8) &&
        BinaryPrimitives.ReadUInt32LittleEndian(payload[4..]) == 32;

    /// <summary>
    /// FC5 derives a 16-byte AES key with CNG's HASH KDF after the signed
    /// OldRVSecure ECDH exchange. The client public key is its CONNECT ECK1
    /// payload; its matching private key remains inside <paramref name="agreement"/>.
    /// </summary>
    private static byte[] DeriveSecureSessionKey(ECDiffieHellman agreement, ReadOnlySpan<byte> clientBlob)
    {
        if (!IsP256EcdhBlob(clientBlob))
            throw new CryptographicException("secure CONNECT did not contain an ECK1 P-256 public key");

        ECParameters parameters = new()
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = clientBlob.Slice(8, 32).ToArray(),
                Y = clientBlob.Slice(40, 32).ToArray(),
            },
        };
        using ECDiffieHellman client = ECDiffieHellman.Create(parameters);
        byte[] sharedHash = agreement.DeriveKeyFromHash(client.PublicKey, HashAlgorithmName.SHA1);
        try
        {
            if (sharedHash.Length < 16)
                throw new CryptographicException("ECDH HASH KDF produced fewer than 16 bytes");
            return sharedHash.AsSpan(0, 16).ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedHash);
        }
    }

    /// <summary>
    /// Secure RMC DATA is an IV-prefixed AES-CBC/PKCS7 envelope. Decrypts and
    /// logs protocol/method (never the raw ticket payload), and for
    /// LoginProtocol::LoginWithToken_V1 only builds a reply.
    ///
    /// UNVERIFIED: the reply body is a best-effort construction
    /// </summary>
    private static byte[]? HandleSecureLoginData(PrudpPacketV0 request, IPEndPoint source, Peer peer, QuazalSettings settings)
    {
        try
        {
            byte[] clear = DecryptSecureData(peer.SecureSessionKey!, request.Payload);
            try
            {
                if (!TryDecompressSecureRmc(clear, out byte[] rmc))
                {
                    Log.Warning("[quazal] secure DATA seq={Sequence} from {Source} decrypted ({Length} bytes) but is not the expected compressed RMC envelope",
                        request.SequenceId, source, clear.Length);
                    return null;
                }

                if (!NamedRmcMessage.TryParse(rmc, out NamedRmcMessage message))
                {
                    int headerOnlyLength = Math.Min(70, rmc.Length);
                    Log.Warning("[quazal] secure DATA seq={Sequence} from {Source} decrypted ({Length} bytes) but is not a well-formed named-RMC message; header={Header}",
                        request.SequenceId, source, rmc.Length, Convert.ToHexString(rmc.AsSpan(0, headerOnlyLength)));
                    return null;
                }
                Log.Information("[quazal] decrypted secure RMC from {Source}: protocol={Protocol} method={Method} callId={CallId} rmcBytes={Length}",
                    source, message.Protocol, message.Method, message.CallId, rmc.Length);

                byte[]? result = message.Protocol switch
                {
                    "LoginProtocol" when message.Method.Contains("LoginWithToken", StringComparison.Ordinal) =>
                        BuildLoginResult(),
                    "LoginProtocol" when message.Method.Contains("Register", StringComparison.Ordinal) =>
                        BuildRegisterResult(),
                    _ => null,
                };
                if (result is null)
                    return null;

                byte[] response = message.BuildResponse(result, ++peer.RmcResponseCounter, settings.PublicHost, settings.Ports[0]);
                byte[] compressed = CompressSecureRmc(response);
                byte[] secureResponse = EncryptSecureData(peer.SecureSessionKey!, compressed);
                Log.Information("[quazal] sending {Method} response to {Source} ({Length} plaintext bytes)",
                    message.Method, source, response.Length);
                return SecureDataPacket(request, peer, secureResponse).ToArray(peer.AccessKeyChecksum);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(clear);
            }
        }
        catch (CryptographicException ex)
        {
            Log.Warning("[quazal] failed to decrypt secure DATA seq={Sequence} from {Source}: {Message}",
                request.SequenceId, source, ex.Message);
            return null;
        }
        catch (InvalidDataException ex)
        {
            Log.Warning("[quazal] failed to inflate secure DATA seq={Sequence} from {Source}: {Message}",
                request.SequenceId, source, ex.Message);
            return null;
        }
    }

    /// <summary>
    /// UNVERIFIED: a real LoginWithToken_V1 result carries a 16-byte value
    /// with a trailing 0x0.
    /// </summary>
    private static byte[] BuildLoginResult()
    {
        byte[] result = new byte[17];
        RandomNumberGenerator.Fill(result.AsSpan(0, 16));
        result[16] = 0x00;
        return result;
    }

    /// <summary>
    /// UNVERIFIED: a real Register_V1 result is a 4-byte value (an ID? an RVCID?). 
    /// Same reasoning as <see cref="BuildLoginResult"/>
    /// </summary>
    private static byte[] BuildRegisterResult()
    {
        byte[] result = new byte[4];
        RandomNumberGenerator.Fill(result);
        return result;
    }

    /// <summary>
    /// Parses and rebuilds named-RMC envelope 
    /// </summary>
    private readonly struct NamedRmcMessage(string protocol, string method, uint callId)
    {
        public string Protocol { get; } = protocol;
        public string Method { get; } = method;
        public uint CallId { get; } = callId;

        /// <summary>
        /// Parses an incoming REQUEST (the 5-byte flag+callId shape, not the response's 6-byte shape).
        /// </summary>
        public static bool TryParse(ReadOnlySpan<byte> rmc, out NamedRmcMessage message)
        {
            message = default;
            int offset = 4;
            if (rmc.Length < offset + 2) return false;
            ushort protocolLength = BinaryPrimitives.ReadUInt16LittleEndian(rmc[offset..]);
            offset += 2;
            if (rmc.Length < offset + protocolLength + 1 + 4 + 2) return false;
            string protocol = NulTerminatedAscii(rmc.Slice(offset, protocolLength));
            offset += protocolLength;
            offset += 1; // request flag byte (observed value 1)
            uint callId = BinaryPrimitives.ReadUInt32LittleEndian(rmc[offset..]);
            offset += 4;
            ushort methodLength = BinaryPrimitives.ReadUInt16LittleEndian(rmc[offset..]);
            offset += 2;
            if (rmc.Length < offset + methodLength) return false;
            string method = NulTerminatedAscii(rmc.Slice(offset, methodLength)).TrimEnd('*');
            message = new NamedRmcMessage(protocol, method, callId);
            return true;
        }

        /// <summary>
        /// Builds a reply envelope carrying <paramref name="result"/>, addressed back to our own Quazal listener.
        /// </summary>
        public byte[] BuildResponse(ReadOnlySpan<byte> result, ushort responseOrdinal, string publicHost, int port)
        {
            byte[] protocolBytes = NulTerminatedBytes(Protocol);
            byte[] methodBytes = NulTerminatedBytes(Method + "*");
            byte[] urlBytes = NulTerminatedBytes($"prudp:/address={publicHost};port={port};type=2");

            int bodyLength = 2 + protocolBytes.Length + 1 + 1 + 4 + 2 + methodBytes.Length
                           + result.Length + 2 + urlBytes.Length;
            byte[] response = new byte[sizeof(uint) + bodyLength + sizeof(ushort)];
            int offset = 0;
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(offset), (uint)bodyLength); offset += 4;
            BinaryPrimitives.WriteUInt16LittleEndian(response.AsSpan(offset), (ushort)protocolBytes.Length); offset += 2;
            protocolBytes.CopyTo(response.AsSpan(offset)); offset += protocolBytes.Length;
            response[offset++] = 0x00; // isResponse
            response[offset++] = 0x01; // version
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(offset), CallId); offset += 4;
            BinaryPrimitives.WriteUInt16LittleEndian(response.AsSpan(offset), (ushort)methodBytes.Length); offset += 2;
            methodBytes.CopyTo(response.AsSpan(offset)); offset += methodBytes.Length;
            result.CopyTo(response.AsSpan(offset)); offset += result.Length;
            BinaryPrimitives.WriteUInt16LittleEndian(response.AsSpan(offset), (ushort)urlBytes.Length); offset += 2;
            urlBytes.CopyTo(response.AsSpan(offset)); offset += urlBytes.Length;
            BinaryPrimitives.WriteUInt16LittleEndian(response.AsSpan(offset), responseOrdinal);
            return response;
        }

        private static string NulTerminatedAscii(ReadOnlySpan<byte> withNul) =>
            Encoding.ASCII.GetString(withNul[..^1]);

        private static byte[] NulTerminatedBytes(string value)
        {
            byte[] bytes = new byte[value.Length + 1];
            Encoding.ASCII.GetBytes(value, bytes);
            return bytes;
        }
    }

    private static byte[] DecryptSecureData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> payload)
    {
        if (payload.Length <= 16 || (payload.Length - 16) % 16 != 0)
            throw new CryptographicException($"invalid secure DATA length {payload.Length}");

        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.IV = payload[..16].ToArray();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using ICryptoTransform decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(payload[16..].ToArray(), 0, payload.Length - 16);
    }

    private static bool TryDecompressSecureRmc(ReadOnlySpan<byte> clear, out byte[] rmc)
    {
        rmc = [];
        if (clear.Length < 3 || clear[0] != 0x02)
            return false;

        using MemoryStream compressed = new(clear[1..].ToArray(), writable: false);
        using ZLibStream zlib = new(compressed, CompressionMode.Decompress);
        using MemoryStream output = new();
        zlib.CopyTo(output);
        rmc = output.ToArray();
        return rmc.Length > 0;
    }

    /// <summary>
    /// Mirrors <see cref="DecryptSecureData"/> for the reply direction: a
    /// fresh random 16-byte IV followed by AES-CBC/PKCS7 ciphertext.
    /// </summary>
    private static byte[] EncryptSecureData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext)
    {
        Span<byte> iv = stackalloc byte[16];
        RandomNumberGenerator.Fill(iv);

        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.IV = iv.ToArray();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using ICryptoTransform encryptor = aes.CreateEncryptor();
        byte[] plaintextArray = plaintext.ToArray();
        byte[] ciphertext = encryptor.TransformFinalBlock(plaintextArray, 0, plaintextArray.Length);

        byte[] output = new byte[16 + ciphertext.Length];
        iv.CopyTo(output);
        ciphertext.CopyTo(output, 16);
        return output;
    }

    /// <summary>
    /// Mirrors <see cref="TryDecompressSecureRmc"/>: a 0x02 marker + a zlib stream.
    /// </summary>
    private static byte[] CompressSecureRmc(ReadOnlySpan<byte> rmc)
    {
        using MemoryStream output = new();
        output.WriteByte(0x02);
        using (ZLibStream zlib = new(output, CompressionMode.Compress, leaveOpen: true))
            zlib.Write(rmc);
        return output.ToArray();
    }

    /// <summary>
    /// Frames a reliable server-initiated secure DATA packet.
    /// </summary>
    private static PrudpPacketV0 SecureDataPacket(PrudpPacketV0 request, Peer peer, byte[] encryptedPayload) => new()
    {
        Source = request.Destination,
        Destination = request.Source,
        PacketType = PacketType.Data,
        Flags = PacketFlags.Reliable | PacketFlags.NeedAck,
        SessionId = peer.ServerSessionId,
        Signature = peer.ClientSignature,
        SequenceId = peer.ServerSequenceId++,
        FragmentId = 0,
        Payload = encryptedPayload,
        PayloadSize = (ushort)encryptedPayload.Length,
        Checksum = 0,
    };

    private static void ClearSecureState(Peer peer)
    {
        peer.SecureAgreement?.Dispose();
        peer.SecureAgreement = null;
        peer.SecureConnectSignature = null;
        peer.SecureConnectExtension = null;
        if (peer.SecureSessionKey is not null)
        {
            CryptographicOperations.ZeroMemory(peer.SecureSessionKey);
            peer.SecureSessionKey = null;
        }
    }

    /// <summary>
    /// Acknowledges a client packet.
    /// </summary>
    private static PrudpPacketV0 Acknowledge(PrudpPacketV0 request, Peer peer, uint remoteSignature) => new()
    {
        Source = request.Destination,
        Destination = request.Source,
        PacketType = request.PacketType,
        Flags = PacketFlags.Ack,
        SessionId = peer.ServerSessionId,
        Signature = remoteSignature,
        SequenceId = request.SequenceId,
        ConnectionSignature = 0,
        FragmentId = request.FragmentId,
        Payload = [],
        PayloadSize = 0,
        Checksum = 0,
    };

    private static void LearnChecksumContribution(PrudpPacketV0 request, Peer peer)
    {
        uint zeroKeyChecksum = BinaryPrimitives.ReadUInt32LittleEndian(request.ToArray().AsSpan(^sizeof(uint)));
        uint difference = unchecked(request.Checksum - zeroKeyChecksum);
        if (difference <= byte.MaxValue)
            peer.AccessKeyChecksum = (byte)difference;
        else
            Log.Debug("[quazal] checksum contribution from peer is not legacy-byte-shaped: 0x{Difference:X8}", difference);
    }

    private static uint NewSignature()
    {
        uint value;
        Span<byte> bytes = stackalloc byte[sizeof(uint)];
        do
        {
            RandomNumberGenerator.Fill(bytes);
            value = BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        }
        while (value == 0);
        return value;
    }

    private static byte NewSessionId()
    {
        byte value;
        do
        {
            value = RandomNumberGenerator.GetBytes(1)[0];
        }
        while (value == 0);
        return value;
    }

    public void Dispose()
    {
        _signingIdentity?.Dispose();
        foreach (Peer peer in _peers.Values)
        {
            ClearSecureState(peer);
        }
        _peers.Clear();
    }
}
