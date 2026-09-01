using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Transactions;

internal enum BsvTransactionMonetaryValidationReason
{
    None,
    NegativeOutput,
    OutputExceedsMaximum,
    AggregateExceedsMaximum,
}

internal readonly record struct BsvTransactionMonetaryValidation(
    Hash256 TransactionId,
    BsvTransactionMonetaryValidationReason Reason,
    ulong OutputIndex,
    long OutputValueSatoshis,
    long TotalOutputValueSatoshis)
{
    internal bool IsValid => Reason == BsvTransactionMonetaryValidationReason.None;
}
