using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Relay;

public enum BsvTransactionFetchOutputKind
{
    SendGetData,
    Requested,
    UnexpectedTransaction,
    Received,
    NotFound,
}

public readonly record struct BsvTransactionFetchOutput(
    BsvTransactionFetchOutputKind Kind,
    Hash256 TransactionId);
