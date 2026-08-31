namespace Staffetta.Core.Protocol.Relay;

public enum BsvTransactionBroadcastState
{
    Created,
    InventoryWritePending,
    Announced,
    TransactionWritePending,
    SentToPeer,
    Terminal,
}

public enum BsvTransactionBroadcastTerminalReason
{
    None,
    Rejected,
    Disconnected,
    WireViolation,
    ExternalFailure,
}
