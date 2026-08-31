namespace Staffetta.Core.Protocol.Relay;

public enum BsvTransactionFetchState
{
    Created,
    AwaitingInventory,
    GetDataWritePending,
    Requested,
    Received,
    NotFound,
    Terminal,
}

public enum BsvTransactionFetchTerminalReason
{
    None,
    Disconnected,
    WireViolation,
    ExternalFailure,
}
