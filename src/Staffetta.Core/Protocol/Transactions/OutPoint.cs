using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Transactions;

/// <summary>A transaction identifier and output index, without checking whether the output exists or is spendable.</summary>
public readonly struct OutPoint : IEquatable<OutPoint>
{
    /// <summary>Creates an output reference, preserving raw values including coinbase sentinel values.</summary>
    /// <param name="transactionId">The referenced transaction identifier in wire order.</param>
    /// <param name="outputIndex">The zero-based output index, or a protocol sentinel value.</param>
    public OutPoint(Hash256 transactionId, uint outputIndex)
    {
        TransactionId = transactionId;
        OutputIndex = outputIndex;
    }

    /// <summary>Gets the referenced transaction identifier in wire order.</summary>
    public Hash256 TransactionId { get; }

    /// <summary>Gets the raw output index, including possible protocol sentinel values.</summary>
    public uint OutputIndex { get; }

    /// <inheritdoc/>
    public bool Equals(OutPoint other) =>
        TransactionId == other.TransactionId && OutputIndex == other.OutputIndex;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is OutPoint other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(TransactionId, OutputIndex);

    /// <summary>Tests equality of both the transaction identifier and output index.</summary>
    public static bool operator ==(OutPoint left, OutPoint right) => left.Equals(right);

    /// <summary>Tests whether the transaction identifier or output index differs.</summary>
    public static bool operator !=(OutPoint left, OutPoint right) => !left.Equals(right);
}
