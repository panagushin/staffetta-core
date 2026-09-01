using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

public enum MerkleBranchNodeKind
{
    Hash,
    DuplicateCurrent,
}

public readonly struct MerkleBranchNode
{
    private readonly Hash256 _hash;

    public MerkleBranchNode(Hash256 hash)
    {
        Kind = MerkleBranchNodeKind.Hash;
        _hash = hash;
    }

    private MerkleBranchNode(MerkleBranchNodeKind kind)
    {
        Kind = kind;
        _hash = default;
    }

    public MerkleBranchNodeKind Kind { get; }

    public static MerkleBranchNode DuplicateCurrent { get; } =
        new(MerkleBranchNodeKind.DuplicateCurrent);

    public bool TryGetHash(out Hash256 hash)
    {
        hash = Kind == MerkleBranchNodeKind.Hash ? _hash : default;
        return Kind == MerkleBranchNodeKind.Hash;
    }
}

public enum MerkleInclusionVerification
{
    NotEvaluated,
    Verified,
    BranchExceedsTransactionIndexWidth,
    TransactionIndexHasUnprovenHighBits,
    DuplicateCurrentCannotBeLeftSibling,
    PathVisibleDuplicateHash,
    UnsupportedBranchNodeKind,
    RootMismatch,
}

public static class MerkleInclusionVerifier
{
    private const int MaximumBranchLength = sizeof(ulong) * 8;

    // A successful result proves only that the transaction id hashes through the supplied path to
    // the supplied root. DuplicateCurrent is the canonical TSC/BRC-74 encoding; rejecting an equal
    // explicit hash is fail-closed input handling, not authentication of tree geometry or mutation
    // absence. Without a block-level transaction count, the claimed index, full block shape, and
    // duplicates anywhere in the tree are not independently authenticated.
    public static MerkleInclusionVerification Verify(
        Hash256 transactionId,
        ulong transactionIndex,
        ReadOnlySpan<MerkleBranchNode> branch,
        Hash256 expectedMerkleRoot)
    {
        if (branch.Length > MaximumBranchLength)
        {
            return MerkleInclusionVerification.BranchExceedsTransactionIndexWidth;
        }

        Hash256 current = transactionId;
        Span<byte> pair = stackalloc byte[Hash256.Length * 2];
        foreach (MerkleBranchNode node in branch)
        {
            bool siblingIsLeft = (transactionIndex & 1) != 0;
            switch (node.Kind)
            {
                case MerkleBranchNodeKind.Hash:
                    _ = node.TryGetHash(out Hash256 sibling);
                    if (sibling == current)
                    {
                        return MerkleInclusionVerification.PathVisibleDuplicateHash;
                    }

                    if (siblingIsLeft)
                    {
                        sibling.WriteWireBytesTo(pair);
                        current.WriteWireBytesTo(pair[Hash256.Length..]);
                    }
                    else
                    {
                        current.WriteWireBytesTo(pair);
                        sibling.WriteWireBytesTo(pair[Hash256.Length..]);
                    }

                    break;

                case MerkleBranchNodeKind.DuplicateCurrent:
                    if (siblingIsLeft)
                    {
                        return MerkleInclusionVerification.DuplicateCurrentCannotBeLeftSibling;
                    }

                    current.WriteWireBytesTo(pair);
                    current.WriteWireBytesTo(pair[Hash256.Length..]);
                    break;

                default:
                    return MerkleInclusionVerification.UnsupportedBranchNodeKind;
            }

            current = Hash256.DoubleSha256(pair);
            transactionIndex >>= 1;
        }

        if (transactionIndex != 0)
        {
            return MerkleInclusionVerification.TransactionIndexHasUnprovenHighBits;
        }

        return current == expectedMerkleRoot
            ? MerkleInclusionVerification.Verified
            : MerkleInclusionVerification.RootMismatch;
    }
}
