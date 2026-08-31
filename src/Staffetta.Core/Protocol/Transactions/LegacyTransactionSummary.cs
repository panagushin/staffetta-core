using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Transactions;

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

    public int Version { get; }

    public ulong InputCount { get; }

    public ulong OutputCount { get; }

    public ulong TotalInputScriptLength { get; }

    public ulong TotalOutputScriptLength { get; }

    public uint LockTime { get; }

    public ulong SerializedLength { get; }

    public Hash256 TransactionId { get; }
}
