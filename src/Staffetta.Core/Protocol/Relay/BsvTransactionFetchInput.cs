using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Relay;

public enum BsvTransactionFetchInputKind
{
    None,
    PeerInventory,
    GetDataWriteCommitted,
    PeerTransaction,
    PeerNotFound,
    Disconnected,
    WireViolation,
    ExternalFailure,
}

public readonly record struct BsvTransactionFetchInput(
    BsvTransactionFetchInputKind Kind,
    Hash256 TransactionId)
{
    public static BsvTransactionFetchInput PeerInventory(Hash256 transactionId) =>
        new(BsvTransactionFetchInputKind.PeerInventory, transactionId);

    public static BsvTransactionFetchInput GetDataWriteCommitted(Hash256 transactionId) =>
        new(BsvTransactionFetchInputKind.GetDataWriteCommitted, transactionId);

    public static BsvTransactionFetchInput PeerTransaction(Hash256 computedTransactionId) =>
        new(BsvTransactionFetchInputKind.PeerTransaction, computedTransactionId);

    public static BsvTransactionFetchInput PeerNotFound(Hash256 transactionId) =>
        new(BsvTransactionFetchInputKind.PeerNotFound, transactionId);

    public static BsvTransactionFetchInput Disconnected() =>
        new(BsvTransactionFetchInputKind.Disconnected, default);

    public static BsvTransactionFetchInput WireViolation() =>
        new(BsvTransactionFetchInputKind.WireViolation, default);

    public static BsvTransactionFetchInput ExternalFailure() =>
        new(BsvTransactionFetchInputKind.ExternalFailure, default);
}
