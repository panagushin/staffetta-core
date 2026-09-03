namespace Staffetta.Core.Protocol.Handshake;

/// <summary>Identifies a validated peer event or caller-reported failure.</summary>
public enum BsvHandshakeInputKind
{
    /// <summary>No event; invalid for an active handshake.</summary>
    None,
    /// <summary>A validated peer version with protocol version and nonce.</summary>
    PeerVersion,
    /// <summary>A validated empty peer verack.</summary>
    PeerVerack,
    /// <summary>A validated protoconf receive-limit advertisement.</summary>
    PeerProtoconf,
    /// <summary>A validated peer ping nonce to echo.</summary>
    PeerPing,
    /// <summary>A validated peer pong nonce to correlate.</summary>
    PeerPong,
    /// <summary>A validated peer reject; its full contents remain with the caller.</summary>
    PeerReject,
    /// <summary>A wire or payload validation failure reported by the caller.</summary>
    WireViolation,
    /// <summary>A non-protocol failure reported by the caller.</summary>
    ExternalFailure,
}

/// <summary>A copied event supplied after frame and payload validation.</summary>
public readonly struct BsvHandshakeInput
{
    private BsvHandshakeInput(BsvHandshakeInputKind kind, int protocolVersion, ulong value)
    {
        Kind = kind;
        ProtocolVersion = protocolVersion;
        Value = value;
    }

    /// <summary>Gets the event kind that determines how the remaining fields are interpreted.</summary>
    public BsvHandshakeInputKind Kind { get; }

    /// <summary>Gets the peer protocol version for PeerVersion; otherwise zero.</summary>
    public int ProtocolVersion { get; }

    /// <summary>Gets the nonce for version/ping/pong, the receive limit for protoconf, or zero for other events.</summary>
    public ulong Value { get; }

    /// <summary>Reports a validated version's protocol version and peer nonce.</summary>
    public static BsvHandshakeInput PeerVersion(int protocolVersion, ulong nonce) =>
        new(BsvHandshakeInputKind.PeerVersion, protocolVersion, nonce);

    /// <summary>Reports a validated empty verack.</summary>
    public static BsvHandshakeInput PeerVerack() => new(BsvHandshakeInputKind.PeerVerack, 0, 0);

    /// <summary>Reports a validated protoconf's maximum receive payload length in bytes.</summary>
    public static BsvHandshakeInput PeerProtoconf(uint maximumReceivePayloadLength) =>
        new(BsvHandshakeInputKind.PeerProtoconf, 0, maximumReceivePayloadLength);

    /// <summary>Reports the nonce of a validated peer ping.</summary>
    public static BsvHandshakeInput PeerPing(ulong nonce) =>
        new(BsvHandshakeInputKind.PeerPing, 0, nonce);

    /// <summary>Reports the nonce of a validated peer pong.</summary>
    public static BsvHandshakeInput PeerPong(ulong nonce) =>
        new(BsvHandshakeInputKind.PeerPong, 0, nonce);

    /// <summary>Reports a validated reject while leaving its full contents with the caller.</summary>
    public static BsvHandshakeInput PeerReject() => new(BsvHandshakeInputKind.PeerReject, 0, 0);

    /// <summary>Reports malformed wire data; no payload is retained.</summary>
    public static BsvHandshakeInput WireViolation() => new(BsvHandshakeInputKind.WireViolation, 0, 0);

    /// <summary>Reports an external failure such as a caller-owned timeout or transport error.</summary>
    public static BsvHandshakeInput ExternalFailure() =>
        new(BsvHandshakeInputKind.ExternalFailure, 0, 0);
}
