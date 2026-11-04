using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

internal sealed class StreamingMerkleTree(IBlockSink sink)
{
    private readonly Hash256[] frontier = new Hash256[64];
    private ulong count;
    internal bool Mutated { get; private set; }

    internal void Reset() { count = 0; Mutated = false; frontier.AsSpan().Clear(); }

    internal void Add(Hash256 hash)
    {
        if (count == ulong.MaxValue) { throw new OverflowException(); }
        var index = count;
        sink.OnMerkleNode(0, index, hash);
        var level = 0;
        for (var occupied = count; (occupied & 1) != 0; occupied >>= 1)
        {
            Mutated |= frontier[level] == hash;
            hash = Pair(frontier[level], hash);
            level++;
            sink.OnMerkleNode(level, index >> level, hash);
        }
        frontier[level] = hash;
        count++;
    }

    internal Hash256 Finish()
    {
        var level = System.Numerics.BitOperations.TrailingZeroCount(count);
        var hash = frontier[level];
        var index = (count - 1) >> level;
        while (index != 0)
        {
            if ((index & 1) != 0)
            {
                Mutated |= frontier[level] == hash;
                hash = Pair(frontier[level], hash);
            }
            else { hash = Pair(hash, hash); }
            index >>= 1;
            sink.OnMerkleNode(++level, index, hash);
        }
        return hash;
    }

    private static Hash256 Pair(Hash256 left, Hash256 right)
    {
        Span<byte> bytes = stackalloc byte[64];
        left.TryCopyWireBytesTo(bytes, out _);
        right.TryCopyWireBytesTo(bytes[32..], out _);
        return Hash256.DoubleSha256(bytes);
    }
}
