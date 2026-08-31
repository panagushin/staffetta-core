using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Relay;

public enum BsvTransactionBroadcastInputKind
{
    None,
    InventoryWriteCommitted,
    PeerGetData,
    TransactionWriteCommitted,
    PeerInventory,
    CorrelatedTransactionReject,
    Disconnected,
    WireViolation,
    ExternalFailure,
}

public readonly record struct BsvTransactionBroadcastInput(
    BsvTransactionBroadcastInputKind Kind,
    Hash256 TransactionId)
{
    public static BsvTransactionBroadcastInput InventoryWriteCommitted(Hash256 transactionId) =>
        new(BsvTransactionBroadcastInputKind.InventoryWriteCommitted, transactionId);

    public static BsvTransactionBroadcastInput PeerGetData(Hash256 transactionId) =>
        new(BsvTransactionBroadcastInputKind.PeerGetData, transactionId);

    public static BsvTransactionBroadcastInput TransactionWriteCommitted(Hash256 transactionId) =>
        new(BsvTransactionBroadcastInputKind.TransactionWriteCommitted, transactionId);

    public static BsvTransactionBroadcastInput PeerInventory(Hash256 transactionId) =>
        new(BsvTransactionBroadcastInputKind.PeerInventory, transactionId);

    /// <summary>
    /// Reports a validated reject whose message command is exactly <c>tx</c> and whose data is
    /// exactly the 32-byte target transaction hash. Reject code and reason remain adapter data.
    /// </summary>
    public static BsvTransactionBroadcastInput CorrelatedTransactionReject(Hash256 transactionId) =>
        new(BsvTransactionBroadcastInputKind.CorrelatedTransactionReject, transactionId);

    public static BsvTransactionBroadcastInput Disconnected() =>
        new(BsvTransactionBroadcastInputKind.Disconnected, default);

    public static BsvTransactionBroadcastInput WireViolation() =>
        new(BsvTransactionBroadcastInputKind.WireViolation, default);

    public static BsvTransactionBroadcastInput ExternalFailure() =>
        new(BsvTransactionBroadcastInputKind.ExternalFailure, default);
}
