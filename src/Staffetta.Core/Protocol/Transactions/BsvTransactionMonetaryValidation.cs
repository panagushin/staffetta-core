using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Transactions;

/// <summary>The independent BSV monetary-range result for a structurally and frame-validated transaction.</summary>
public enum BsvTransactionMonetaryValidationReason
{
    /// <summary>Every output and the aggregate output amount are within the BSV money range.</summary>
    None,
    /// <summary>An output has a negative amount.</summary>
    NegativeOutput,
    /// <summary>One output exceeds the maximum BSV money supply.</summary>
    OutputExceedsMaximum,
    /// <summary>The sum of outputs exceeds the maximum BSV money supply.</summary>
    AggregateExceedsMaximum,
}

/// <summary>Monetary-range evidence independent from scripts, input existence, and consensus acceptance.</summary>
/// <param name="TransactionId">The identity computed from the fully validated enclosing payload.</param>
/// <param name="Reason">The first monetary-range failure, or None for success.</param>
/// <param name="OutputIndex">The first invalid output index, meaningful only for failure.</param>
/// <param name="OutputValueSatoshis">The first invalid output amount, meaningful only for failure.</param>
/// <param name="TotalOutputValueSatoshis">The valid total, or the total at the first failure.</param>
public readonly record struct BsvTransactionMonetaryValidation(
    Hash256 TransactionId,
    BsvTransactionMonetaryValidationReason Reason,
    ulong OutputIndex,
    long OutputValueSatoshis,
    long TotalOutputValueSatoshis)
{
    /// <summary>Gets whether monetary range checks succeeded; this is not full transaction validity.</summary>
    public bool IsValid => Reason == BsvTransactionMonetaryValidationReason.None;
}
