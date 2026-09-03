using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Transactions;

/// <summary>Copied metadata and transaction identifier from a committed structural legacy-transaction parse.</summary>
/// <remarks>A summary is not evidence of monetary, script, UTXO, consensus, or chain-inclusion validity.</remarks>
public readonly struct LegacyTransactionSummary
{
    internal LegacyTransactionSummary(
        int version,
        ulong inputCount,
        ulong outputCount,
        ulong totalInputScriptLength,
        ulong totalOutputScriptLength,
        uint lockTime,
        ulong serializedLength,
        Hash256 transactionId)
    {
        Version = version;
        InputCount = inputCount;
        OutputCount = outputCount;
        TotalInputScriptLength = totalInputScriptLength;
        TotalOutputScriptLength = totalOutputScriptLength;
        LockTime = lockTime;
        SerializedLength = serializedLength;
        TransactionId = transactionId;
    }

    /// <summary>Gets the raw signed transaction version.</summary>
    public int Version { get; }

    /// <summary>Gets the number of parsed inputs.</summary>
    public ulong InputCount { get; }

    /// <summary>Gets the number of parsed outputs.</summary>
    public ulong OutputCount { get; }

    /// <summary>Gets the total number of input-script bytes, excluding length prefixes.</summary>
    public ulong TotalInputScriptLength { get; }

    /// <summary>Gets the total number of output-script bytes, excluding length prefixes.</summary>
    public ulong TotalOutputScriptLength { get; }

    /// <summary>Gets the raw lock-time field; transaction finality has not been evaluated.</summary>
    public uint LockTime { get; }

    /// <summary>Gets the exact transaction byte length, excluding framing and trailing bytes.</summary>
    public ulong SerializedLength { get; }

    /// <summary>Gets double SHA-256 of the serialized transaction, represented in wire order.</summary>
    public Hash256 TransactionId { get; }
}
