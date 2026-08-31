namespace Staffetta.Core.Protocol.Handshake;

public enum BsvHandshakeOutputKind
{
    SendVersion,
    SendVerack,
    SendProtoconf,
    BecameReady,
    SendPong,
    SendPing,
    PingAcknowledged,
    ForwardReject,
}

public readonly record struct BsvHandshakeOutput(BsvHandshakeOutputKind Kind, ulong Value = 0);
