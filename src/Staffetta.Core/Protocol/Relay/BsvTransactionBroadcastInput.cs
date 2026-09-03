using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Relay;

/// <summary>Identifies a write commitment, validated peer event, or caller-reported broadcast failure.</summary>
public enum BsvTransactionBroadcastInputKind
{
    /// <summary>No event; invalid for an active broadcast.</summary>
    None,
    /// <summary>The caller confirms the complete target inventory frame was written.</summary>
    InventoryWriteCommitted,
    /// <summary>A validated peer getdata entry identifies a transaction.</summary>
    PeerGetData,
    /// <summary>The caller confirms the complete target transaction frame was written.</summary>
    TransactionWriteCommitted,
    /// <summary>A validated peer inventory identifies a transaction; not proof of onward relay.</summary>
    PeerInventory,
    /// <summary>A validated tx reject contains exactly the target's 32-byte hash.</summary>
    CorrelatedTransactionReject,
    /// <summary>The caller reports peer disconnection.</summary>
    Disconnected,
    /// <summary>The caller reports malformed wire data.</summary>
    WireViolation,
    /// <summary>The caller reports a non-protocol failure.</summary>
    ExternalFailure,
}

/// <summary>A copied broadcast input carrying an event kind and transaction identity, never transaction bytes.</summary>
/// <param name="Kind">The event kind.</param>
/// <param name="TransactionId">The event's transaction identifier, ignored for disconnection and failure events.</param>
public readonly record struct BsvTransactionBroadcastInput(
    BsvTransactionBroadcastInputKind Kind,
    Hash256 TransactionId)
{
    /// <summary>Confirms the complete inventory frame write, not merely a queued send intent.</summary>
    public static BsvTransactionBroadcastInput InventoryWriteCommitted(Hash256 transactionId) =>
        new(BsvTransactionBroadcastInputKind.InventoryWriteCommitted, transactionId);

    /// <summary>Reports a validated peer transaction request.</summary>
    public static BsvTransactionBroadcastInput PeerGetData(Hash256 transactionId) =>
        new(BsvTransactionBroadcastInputKind.PeerGetData, transactionId);

    /// <summary>Confirms the complete transaction frame write, not peer acceptance or onward relay.</summary>
    public static BsvTransactionBroadcastInput TransactionWriteCommitted(Hash256 transactionId) =>
        new(BsvTransactionBroadcastInputKind.TransactionWriteCommitted, transactionId);

    /// <summary>Reports a validated peer transaction inventory, without claiming onward relay.</summary>
    public static BsvTransactionBroadcastInput PeerInventory(Hash256 transactionId) =>
        new(BsvTransactionBroadcastInputKind.PeerInventory, transactionId);

    /// <summary>
    /// Reports a validated reject whose message command is exactly <c>tx</c> and whose data is
    /// exactly the 32-byte target transaction hash. Reject code and reason remain adapter data.
    /// </summary>
    public static BsvTransactionBroadcastInput CorrelatedTransactionReject(Hash256 transactionId) =>
        new(BsvTransactionBroadcastInputKind.CorrelatedTransactionReject, transactionId);

    /// <summary>Reports that the peer disconnected.</summary>
    public static BsvTransactionBroadcastInput Disconnected() =>
        new(BsvTransactionBroadcastInputKind.Disconnected, default);

    /// <summary>Reports a wire or payload validation failure.</summary>
    public static BsvTransactionBroadcastInput WireViolation() =>
        new(BsvTransactionBroadcastInputKind.WireViolation, default);

    /// <summary>Reports a caller-owned timeout, transport error, or other external failure.</summary>
    public static BsvTransactionBroadcastInput ExternalFailure() =>
        new(BsvTransactionBroadcastInputKind.ExternalFailure, default);
}
