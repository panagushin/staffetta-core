using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

/// <summary>The six fields of an 80-byte block header, without a claim of consensus validity.</summary>
public readonly struct BlockHeader : IEquatable<BlockHeader>
{
    internal BlockHeader(
        int version,
        Hash256 previousBlockHash,
        Hash256 merkleRoot,
        uint timestamp,
        uint bits,
        uint nonce)
    {
        Version = version;
        PreviousBlockHash = previousBlockHash;
        MerkleRoot = merkleRoot;
        Timestamp = timestamp;
        Bits = bits;
        Nonce = nonce;
    }

    /// <summary>Gets the raw signed header version.</summary>
    public int Version { get; }

    /// <summary>Gets the previous block identifier in wire order.</summary>
    public Hash256 PreviousBlockHash { get; }

    /// <summary>Gets the declared transaction Merkle root in wire order.</summary>
    public Hash256 MerkleRoot { get; }

    /// <summary>Gets the declared timestamp in Unix seconds, without time-validity checks.</summary>
    public uint Timestamp { get; }

    /// <summary>Gets the raw compact proof-of-work target encoding.</summary>
    public uint Bits { get; }

    /// <summary>Gets the proof-of-work nonce.</summary>
    public uint Nonce { get; }

    /// <summary>Computes double SHA-256 over the 80-byte header without validating proof of work.</summary>
    /// <returns>The block identifier in wire order.</returns>
    public Hash256 ComputeHash()
    {
        Span<byte> encoded = stackalloc byte[BlockHeaderCodec.EncodedLength];
        BlockHeaderCodec.WriteUnchecked(encoded, this);
        return Hash256.DoubleSha256(encoded);
    }

    /// <inheritdoc/>
    public bool Equals(BlockHeader other) =>
        Version == other.Version &&
        PreviousBlockHash == other.PreviousBlockHash &&
        MerkleRoot == other.MerkleRoot &&
        Timestamp == other.Timestamp &&
        Bits == other.Bits &&
        Nonce == other.Nonce;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is BlockHeader other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(Version, PreviousBlockHash, MerkleRoot, Timestamp, Bits, Nonce);

    /// <summary>Tests equality of all six header fields.</summary>
    public static bool operator ==(BlockHeader left, BlockHeader right) => left.Equals(right);

    /// <summary>Tests whether any header field differs.</summary>
    public static bool operator !=(BlockHeader left, BlockHeader right) => !left.Equals(right);
}
