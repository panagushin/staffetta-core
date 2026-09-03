namespace Staffetta.Core.Protocol.Relay;

/// <summary>The transport-free phase of one transaction advertisement to one peer.</summary>
public enum BsvTransactionBroadcastState
{
    /// <summary>No target transaction has been selected.</summary>
    Created,
    /// <summary>An inventory intent exists but its write is not committed.</summary>
    InventoryWritePending,
    /// <summary>The inventory write is committed; no transaction write is pending.</summary>
    Announced,
    /// <summary>A peer request produced a transaction intent awaiting write commitment.</summary>
    TransactionWritePending,
    /// <summary>The transaction write committed; peer acceptance or onward relay is not implied.</summary>
    SentToPeer,
    /// <summary>A reject or failure ended processing; later inputs are ignored.</summary>
    Terminal,
}

/// <summary>The reason a one-peer transaction advertisement stopped.</summary>
public enum BsvTransactionBroadcastTerminalReason
{
    /// <summary>No terminal reason has been recorded.</summary>
    None,
    /// <summary>A target-correlated reject was accepted after the transaction write committed.</summary>
    Rejected,
    /// <summary>The caller reported peer disconnection.</summary>
    Disconnected,
    /// <summary>The caller reported invalid wire data.</summary>
    WireViolation,
    /// <summary>The caller reported a non-protocol failure.</summary>
    ExternalFailure,
}
