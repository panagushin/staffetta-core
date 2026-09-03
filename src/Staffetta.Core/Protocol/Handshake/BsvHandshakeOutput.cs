namespace Staffetta.Core.Protocol.Handshake;

/// <summary>Identifies a handshake send intent or accepted protocol observation.</summary>
public enum BsvHandshakeOutputKind
{
    /// <summary>Intent to send a version using the local nonce; not a write-committed fact.</summary>
    SendVersion,
    /// <summary>Intent to send an empty verack; not a write-committed fact.</summary>
    SendVerack,
    /// <summary>Intent to send the caller's local protocol configuration.</summary>
    SendProtoconf,
    /// <summary>Peer version and verack were accepted and local response intents emitted.</summary>
    BecameReady,
    /// <summary>Intent to echo the peer nonce in a pong.</summary>
    SendPong,
    /// <summary>Intent to send the supplied nonce in a ping.</summary>
    SendPing,
    /// <summary>A validated pong matched the outstanding local ping nonce.</summary>
    PingAcknowledged,
    /// <summary>A validated reject received after readiness should be handled by the caller.</summary>
    ForwardReject,
}

/// <summary>A handshake output; send intents require transport work before they become wire-write facts.</summary>
/// <param name="Kind">The output kind.</param>
/// <param name="Value">The nonce for SendVersion, SendPing, SendPong, or PingAcknowledged; otherwise zero.</param>
public readonly record struct BsvHandshakeOutput(BsvHandshakeOutputKind Kind, ulong Value = 0);
