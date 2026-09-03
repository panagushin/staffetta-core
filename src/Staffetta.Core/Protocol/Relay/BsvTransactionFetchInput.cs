using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Relay;

/// <summary>Identifies a validated peer event, request write commitment, or fetch failure.</summary>
public enum BsvTransactionFetchInputKind
{
    /// <summary>No event; invalid for an active fetch.</summary>
    None,
    /// <summary>A validated peer inventory entry identifies a transaction.</summary>
    PeerInventory,
    /// <summary>The caller confirms the complete target getdata frame was written.</summary>
    GetDataWriteCommitted,
    /// <summary>A structurally and frame-validated transaction has the supplied computed identifier.</summary>
    PeerTransaction,
    /// <summary>A validated peer notfound entry identifies a transaction.</summary>
    PeerNotFound,
    /// <summary>The caller reports peer disconnection.</summary>
    Disconnected,
    /// <summary>The caller reports malformed wire data.</summary>
    WireViolation,
    /// <summary>The caller reports a non-protocol failure.</summary>
    ExternalFailure,
}

/// <summary>A copied fetch input carrying an event kind and transaction identity, never transaction bytes.</summary>
/// <param name="Kind">The event kind.</param>
/// <param name="TransactionId">The event's transaction identifier, ignored for disconnection and failure events.</param>
public readonly record struct BsvTransactionFetchInput(
    BsvTransactionFetchInputKind Kind,
    Hash256 TransactionId)
{
    /// <summary>Reports a validated peer transaction inventory.</summary>
    public static BsvTransactionFetchInput PeerInventory(Hash256 transactionId) =>
        new(BsvTransactionFetchInputKind.PeerInventory, transactionId);

    /// <summary>Confirms the complete getdata frame write, not merely a queued request.</summary>
    public static BsvTransactionFetchInput GetDataWriteCommitted(Hash256 transactionId) =>
        new(BsvTransactionFetchInputKind.GetDataWriteCommitted, transactionId);

    /// <summary>Reports the computed identifier of a complete, structurally and frame-validated transaction, including unsolicited transactions.</summary>
    public static BsvTransactionFetchInput PeerTransaction(Hash256 computedTransactionId) =>
        new(BsvTransactionFetchInputKind.PeerTransaction, computedTransactionId);

    /// <summary>Reports a validated peer notfound entry for this transaction.</summary>
    public static BsvTransactionFetchInput PeerNotFound(Hash256 transactionId) =>
        new(BsvTransactionFetchInputKind.PeerNotFound, transactionId);

    /// <summary>Reports that the peer disconnected.</summary>
    public static BsvTransactionFetchInput Disconnected() =>
        new(BsvTransactionFetchInputKind.Disconnected, default);

    /// <summary>Reports a wire or payload validation failure.</summary>
    public static BsvTransactionFetchInput WireViolation() =>
        new(BsvTransactionFetchInputKind.WireViolation, default);

    /// <summary>Reports a caller-owned timeout, transport error, or other external failure.</summary>
    public static BsvTransactionFetchInput ExternalFailure() =>
        new(BsvTransactionFetchInputKind.ExternalFailure, default);
}
