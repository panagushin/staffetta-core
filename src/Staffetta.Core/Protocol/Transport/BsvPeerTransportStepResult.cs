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

internal enum BsvPeerTransportDriveKind
{
    Progress,
    NeedsPeerRead,
    Terminal,
}

internal readonly record struct BsvPeerTransportDriveResult(
    BsvPeerTransportDriveKind Kind,
    BsvPeerTransportStepResult StepResult)
{
    internal static BsvPeerTransportDriveResult Progress =>
        new(BsvPeerTransportDriveKind.Progress, BsvPeerTransportStepResult.Progress);

    internal static BsvPeerTransportDriveResult NeedsPeerRead =>
        new(BsvPeerTransportDriveKind.NeedsPeerRead, default);

    internal static BsvPeerTransportDriveResult Terminal(BsvPeerTransportStepResult result) =>
        new(BsvPeerTransportDriveKind.Terminal, result);
}
