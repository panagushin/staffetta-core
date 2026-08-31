namespace Staffetta.Core.Protocol.Handshake;

public enum BsvHandshakeState
{
    Created,
    Negotiating,
    Ready,
    Terminal,
}

public enum BsvHandshakeTerminalReason
{
    None,
    DuplicateVersion,
    SelfConnection,
    UnsupportedProtocolVersion,
    EarlyProtoconf,
    DuplicateProtoconf,
    InsufficientPeerReceiveLimit,
    RejectBeforeReady,
    WireViolation,
    ExternalFailure,
}
