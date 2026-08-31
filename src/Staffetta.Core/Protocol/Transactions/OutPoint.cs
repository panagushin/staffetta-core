using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Transactions;

public readonly struct OutPoint : IEquatable<OutPoint>
{
    public OutPoint(Hash256 transactionId, uint outputIndex)
    {
        TransactionId = transactionId;
        OutputIndex = outputIndex;
    }

    public Hash256 TransactionId { get; }

    public uint OutputIndex { get; }

    public bool Equals(OutPoint other) =>
        TransactionId == other.TransactionId && OutputIndex == other.OutputIndex;

    public override bool Equals(object? obj) => obj is OutPoint other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(TransactionId, OutputIndex);

    public static bool operator ==(OutPoint left, OutPoint right) => left.Equals(right);

    public static bool operator !=(OutPoint left, OutPoint right) => !left.Equals(right);
}
