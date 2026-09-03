namespace Staffetta.Core.Protocol.Handshake;

/// <summary>The phase of one transport-free handshake.</summary>
public enum BsvHandshakeState
{
    /// <summary>Not yet started; no local version intent has been emitted.</summary>
    Created,
    /// <summary>A local version intent exists and peer version/verack negotiation is in progress.</summary>
    Negotiating,
    /// <summary>Peer version and verack were accepted and local response intents emitted; not proof those intents were written.</summary>
    Ready,
    /// <summary>The handshake ended with a stable terminal reason; further inputs are ignored.</summary>
    Terminal,
}

/// <summary>The reason a handshake entered its terminal state.</summary>
public enum BsvHandshakeTerminalReason
{
    /// <summary>No terminal reason has been recorded.</summary>
    None,
    /// <summary>A second peer version was received after accepting the first.</summary>
    DuplicateVersion,
    /// <summary>The peer nonce matched the caller-supplied local nonce.</summary>
    SelfConnection,
    /// <summary>The peer version was below the configured minimum.</summary>
    UnsupportedProtocolVersion,
    /// <summary>Protoconf arrived before both peer version and verack were accepted.</summary>
    EarlyProtoconf,
    /// <summary>The peer sent protoconf more than once.</summary>
    DuplicateProtoconf,
    /// <summary>The peer advertised a receive limit below the required one-megabyte minimum.</summary>
    InsufficientPeerReceiveLimit,
    /// <summary>A reject arrived before the handshake became ready.</summary>
    RejectBeforeReady,
    /// <summary>The caller reported malformed wire data.</summary>
    WireViolation,
    /// <summary>The caller reported a failure outside the handshake protocol.</summary>
    ExternalFailure,
}
