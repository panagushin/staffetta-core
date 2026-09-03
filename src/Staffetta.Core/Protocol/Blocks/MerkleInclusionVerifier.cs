using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

/// <summary>Identifies an explicit sibling hash or a directive to duplicate the current path hash.</summary>
public enum MerkleBranchNodeKind
{
    /// <summary>An explicit sibling hash, including a possible all-zero hash.</summary>
    Hash,
    /// <summary>A right-hand duplicate of the current hash, not an explicit equal sibling hash.</summary>
    DuplicateCurrent,
}

/// <summary>One leaf-to-root Merkle path step using an explicit hash or a duplicate-current marker.</summary>
public readonly struct MerkleBranchNode
{
    private readonly Hash256 _hash;

    /// <summary>Creates an explicit sibling node; equality with the current path hash is checked during verification.</summary>
    /// <param name="hash">The sibling hash in wire order.</param>
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

    /// <summary>Gets how the sibling at this path step is represented.</summary>
    public MerkleBranchNodeKind Kind { get; }

    /// <summary>Gets the canonical marker requesting duplication of the current hash on its right.</summary>
    public static MerkleBranchNode DuplicateCurrent { get; } =
        new(MerkleBranchNodeKind.DuplicateCurrent);

    /// <summary>Retrieves an explicit sibling hash, if this node contains one.</summary>
    /// <param name="hash">The explicit hash on success; otherwise the default value.</param>
    /// <returns>Whether the node is a <see cref="MerkleBranchNodeKind.Hash"/> node.</returns>
    public bool TryGetHash(out Hash256 hash)
    {
        hash = Kind == MerkleBranchNodeKind.Hash ? _hash : default;
        return Kind == MerkleBranchNodeKind.Hash;
    }
}

/// <summary>The result of checking a supplied transaction-to-root path, not an entire block or chain.</summary>
public enum MerkleInclusionVerification
{
    /// <summary>No verification result has been assigned; this is the default value.</summary>
    NotEvaluated,
    /// <summary>The supplied path hashes to the expected root and passes the path-local checks.</summary>
    Verified,
    /// <summary>The branch contains more than the 64 levels addressable by the transaction index.</summary>
    BranchExceedsTransactionIndexWidth,
    /// <summary>The index has nonzero bits left after all supplied path levels have been consumed.</summary>
    TransactionIndexHasUnprovenHighBits,
    /// <summary>A duplicate-current marker is at a level where the index requires a left sibling.</summary>
    DuplicateCurrentCannotBeLeftSibling,
    /// <summary>An explicit sibling equals the current hash; use the duplicate-current marker when appropriate.</summary>
    PathVisibleDuplicateHash,
    /// <summary>A branch node has an unsupported kind.</summary>
    UnsupportedBranchNodeKind,
    /// <summary>The computed path root does not equal the expected root.</summary>
    RootMismatch,
}

/// <summary>Checks a double-SHA-256 Merkle path using wire-order hash bytes.</summary>
/// <remarks>
/// Success binds the supplied transaction identifier to the supplied root through this path only.
/// Without a block transaction count it does not independently authenticate the claimed index,
/// full tree shape, or absence of duplicate transactions elsewhere. It does not validate a block
/// header or establish selected-chain membership or confirmations.
/// </remarks>
public static class MerkleInclusionVerifier
{
    private const int MaximumBranchLength = sizeof(ulong) * 8;

    // A successful result proves only that the transaction id hashes through the supplied path to
    // the supplied root. DuplicateCurrent is the canonical TSC/BRC-74 encoding; rejecting an equal
    // explicit hash is fail-closed input handling, not authentication of tree geometry or mutation
    // absence. Without a block-level transaction count, the claimed index, full block shape, and
    // duplicates anywhere in the tree are not independently authenticated.
    /// <summary>Hashes a leaf-to-root branch and rejects malformed or ambiguous path steps.</summary>
    /// <param name="transactionId">The transaction identifier used as the leaf, in wire order.</param>
    /// <param name="transactionIndex">The claimed zero-based leaf index; successive low bits select sibling sides.</param>
    /// <param name="branch">Up to 64 steps ordered from the leaf toward the root; not retained.</param>
    /// <param name="expectedMerkleRoot">The root to compare against, in wire order.</param>
    /// <returns>The first failed path check, or <see cref="MerkleInclusionVerification.Verified"/>.</returns>
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
