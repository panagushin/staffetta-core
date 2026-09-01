namespace Staffetta.Core.Protocol.Transport;

internal enum BsvPeerTransportStepKind
{
    Progress,
    PeerClosed,
    Canceled,
    Faulted,
}

internal enum BsvPeerTransportTerminalReason
{
    None,
    PeerClosed,
    TruncatedInput,
    ProtocolViolation,
    Canceled,
    TransportReadFailure,
    TransportWriteFailure,
    TransactionSourceUnavailable,
    TransactionSourceFailure,
    TransactionSourceContractViolation,
    TransactionHashMismatch,
    FactSinkFailure,
    DependencyReentry,
    HandshakeTerminated,
}

internal readonly record struct BsvPeerTransportStepResult(
    BsvPeerTransportStepKind Kind,
    BsvPeerTransportTerminalReason Reason)
{
    internal static BsvPeerTransportStepResult Progress =>
        new(BsvPeerTransportStepKind.Progress, BsvPeerTransportTerminalReason.None);
}
