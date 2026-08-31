namespace Staffetta.Core.Protocol.Handshake;

public enum BsvHandshakeInputKind
{
    None,
    PeerVersion,
    PeerVerack,
    PeerProtoconf,
    PeerPing,
    PeerPong,
    PeerReject,
    WireViolation,
    ExternalFailure,
}

public readonly struct BsvHandshakeInput
{
    private BsvHandshakeInput(BsvHandshakeInputKind kind, int protocolVersion, ulong value)
    {
        Kind = kind;
        ProtocolVersion = protocolVersion;
        Value = value;
    }

    public BsvHandshakeInputKind Kind { get; }

    public int ProtocolVersion { get; }

    public ulong Value { get; }

    public static BsvHandshakeInput PeerVersion(int protocolVersion, ulong nonce) =>
        new(BsvHandshakeInputKind.PeerVersion, protocolVersion, nonce);

    public static BsvHandshakeInput PeerVerack() => new(BsvHandshakeInputKind.PeerVerack, 0, 0);

    public static BsvHandshakeInput PeerProtoconf(uint maximumReceivePayloadLength) =>
        new(BsvHandshakeInputKind.PeerProtoconf, 0, maximumReceivePayloadLength);

    public static BsvHandshakeInput PeerPing(ulong nonce) =>
        new(BsvHandshakeInputKind.PeerPing, 0, nonce);

    public static BsvHandshakeInput PeerPong(ulong nonce) =>
        new(BsvHandshakeInputKind.PeerPong, 0, nonce);

    public static BsvHandshakeInput PeerReject() => new(BsvHandshakeInputKind.PeerReject, 0, 0);

    public static BsvHandshakeInput WireViolation() => new(BsvHandshakeInputKind.WireViolation, 0, 0);

    public static BsvHandshakeInput ExternalFailure() =>
        new(BsvHandshakeInputKind.ExternalFailure, 0, 0);
}
