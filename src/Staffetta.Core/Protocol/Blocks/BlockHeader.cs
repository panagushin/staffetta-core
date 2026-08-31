using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

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

    public int Version { get; }

    public Hash256 PreviousBlockHash { get; }

    public Hash256 MerkleRoot { get; }

    public uint Timestamp { get; }

    public uint Bits { get; }

    public uint Nonce { get; }

    public Hash256 ComputeHash()
    {
        Span<byte> encoded = stackalloc byte[BlockHeaderCodec.EncodedLength];
        BlockHeaderCodec.WriteUnchecked(encoded, this);
        return Hash256.DoubleSha256(encoded);
    }

    public bool Equals(BlockHeader other) =>
        Version == other.Version &&
        PreviousBlockHash == other.PreviousBlockHash &&
        MerkleRoot == other.MerkleRoot &&
        Timestamp == other.Timestamp &&
        Bits == other.Bits &&
        Nonce == other.Nonce;

    public override bool Equals(object? obj) => obj is BlockHeader other && Equals(other);

    public override int GetHashCode() =>
        HashCode.Combine(Version, PreviousBlockHash, MerkleRoot, Timestamp, Bits, Nonce);

    public static bool operator ==(BlockHeader left, BlockHeader right) => left.Equals(right);

    public static bool operator !=(BlockHeader left, BlockHeader right) => !left.Equals(right);
}
