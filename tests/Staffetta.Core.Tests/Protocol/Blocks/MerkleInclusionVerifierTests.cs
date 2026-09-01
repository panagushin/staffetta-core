using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Tests.Protocol.Blocks;

[TestClass]
public sealed class MerkleInclusionVerifierTests
{
    [TestMethod]
    public void SingleTransactionNeedsNoBranch()
    {
        Hash256 transactionId = Leaf(0);

        Assert.AreEqual(
            MerkleInclusionVerification.Verified,
            MerkleInclusionVerifier.Verify(transactionId, 0, [], transactionId));
    }

    [TestMethod]
    public void EvenTreeRespectsLeftAndRightOrderingAtEveryLevel()
    {
        Hash256 leaf0 = Leaf(0);
        Hash256 leaf1 = Leaf(1);
        Hash256 leaf2 = Leaf(2);
        Hash256 leaf3 = Leaf(3);
        Hash256 parent01 = Parent(leaf0, leaf1);
        Hash256 parent23 = Parent(leaf2, leaf3);
        Hash256 root = Parent(parent01, parent23);

        AssertVerified(leaf0, 0, [new(leaf1), new(parent23)], root);
        AssertVerified(leaf1, 1, [new(leaf0), new(parent23)], root);
        AssertVerified(leaf2, 2, [new(leaf3), new(parent01)], root);
        AssertVerified(leaf3, 3, [new(leaf2), new(parent01)], root);
    }

    [TestMethod]
    public void HardcodedWireVectorPinsSha256dByteOrderForBothSides()
    {
        Hash256 left = FromWireHex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        Hash256 right = FromWireHex(
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        Hash256 expectedRoot = FromWireHex(
            "01c9f464780a1b6af4eb400fe2f2896cfb2169f5a65701439e4c2c4e213903ef");

        Assert.AreEqual(
            "ef0339214e2c4c9e430157a6f56921fb6c89f2e20f40ebf46a1b0a7864f4c901",
            expectedRoot.ToDisplayHex());
        AssertVerified(left, 0, [new(right)], expectedRoot);
        AssertVerified(right, 1, [new(left)], expectedRoot);
    }

    [TestMethod]
    public void OddTreeUsesExplicitDuplicateCurrentNodesAtSuccessiveLevels()
    {
        Hash256 leaf0 = Leaf(0);
        Hash256 leaf1 = Leaf(1);
        Hash256 leaf2 = Leaf(2);
        Hash256 leaf3 = Leaf(3);
        Hash256 leaf4 = Leaf(4);
        Hash256 parent01 = Parent(leaf0, leaf1);
        Hash256 parent23 = Parent(leaf2, leaf3);
        Hash256 parent44 = Parent(leaf4, leaf4);
        Hash256 left = Parent(parent01, parent23);
        Hash256 right = Parent(parent44, parent44);
        Hash256 root = Parent(left, right);

        AssertVerified(
            leaf4,
            4,
            [
                MerkleBranchNode.DuplicateCurrent,
                MerkleBranchNode.DuplicateCurrent,
                new(left),
            ],
            root);
    }

    [TestMethod]
    public void WrongSiblingRootAndIndexAreRejectedWithoutCollapsingTheirMeaning()
    {
        Hash256 leaf0 = Leaf(0);
        Hash256 leaf1 = Leaf(1);
        Hash256 root = Parent(leaf0, leaf1);

        Assert.AreEqual(
            MerkleInclusionVerification.RootMismatch,
            MerkleInclusionVerifier.Verify(leaf0, 0, [new(Leaf(9))], root));
        Assert.AreEqual(
            MerkleInclusionVerification.RootMismatch,
            MerkleInclusionVerifier.Verify(leaf0, 0, [new(leaf1)], Leaf(9)));
        Assert.AreEqual(
            MerkleInclusionVerification.RootMismatch,
            MerkleInclusionVerifier.Verify(leaf0, 1, [new(leaf1)], root));
        Assert.AreEqual(
            MerkleInclusionVerification.TransactionIndexHasUnprovenHighBits,
            MerkleInclusionVerifier.Verify(leaf0, 2, [new(leaf1)], root));
    }

    [TestMethod]
    public void DuplicateCurrentCannotStandForAMissingLeftSibling()
    {
        Hash256 leaf = Leaf(0);

        Assert.AreEqual(
            MerkleInclusionVerification.DuplicateCurrentCannotBeLeftSibling,
            MerkleInclusionVerifier.Verify(
                leaf,
                1,
                [MerkleBranchNode.DuplicateCurrent],
                Parent(leaf, leaf)));
    }

    [TestMethod]
    public void EqualExplicitSiblingFailsClosedAndExplicitDuplicateUsesCanonicalEncoding()
    {
        Hash256 leaf = Leaf(0);

        Assert.AreEqual(
            MerkleInclusionVerification.PathVisibleDuplicateHash,
            MerkleInclusionVerifier.Verify(
                leaf,
                0,
                [new MerkleBranchNode(leaf)],
                Parent(leaf, leaf)));
        AssertVerified(
            leaf,
            0,
            [MerkleBranchNode.DuplicateCurrent],
            Parent(leaf, leaf));
    }

    [TestMethod]
    public void SixtyFourNodeBranchConsumesEveryBitOfMaximumUnsignedIndex()
    {
        byte[] transactionWireBytes = CreateSequentialBytes(start: 0);
        Hash256 transactionId = FromWireBytes(transactionWireBytes);
        byte[] currentWireBytes = (byte[])transactionWireBytes.Clone();
        var branch = new MerkleBranchNode[64];
        for (var level = 0; level < branch.Length; level++)
        {
            byte[] siblingWireBytes = CreateSequentialBytes(start: level + 32);
            branch[level] = new MerkleBranchNode(FromWireBytes(siblingWireBytes));

            var pair = new byte[Hash256.Length * 2];
            siblingWireBytes.CopyTo(pair, 0);
            currentWireBytes.CopyTo(pair, Hash256.Length);
            byte[] firstHash = SHA256.HashData(pair);
            currentWireBytes = SHA256.HashData(firstHash);
        }

        Hash256 expectedRoot = FromWireBytes(currentWireBytes);

        AssertVerified(transactionId, ulong.MaxValue, branch, expectedRoot);
        Assert.AreEqual(
            MerkleInclusionVerification.TransactionIndexHasUnprovenHighBits,
            MerkleInclusionVerifier.Verify(
                transactionId,
                ulong.MaxValue,
                branch.AsSpan(0, 63),
                expectedRoot));
    }

    [TestMethod]
    public void BranchCannotExceedTheWidthOfItsUnsignedTransactionIndex()
    {
        var branch = new MerkleBranchNode[65];

        Assert.AreEqual(
            MerkleInclusionVerification.BranchExceedsTransactionIndexWidth,
            MerkleInclusionVerifier.Verify(Leaf(0), 0, branch, Leaf(0)));
    }

    [TestMethod]
    public void RealZeroHashIsAHashNodeRatherThanDuplicateCurrentSentinel()
    {
        Hash256 leaf = Leaf(0);
        Hash256 root = Parent(leaf, default);
        var zeroHashNode = new MerkleBranchNode(default);

        Assert.IsTrue(zeroHashNode.TryGetHash(out Hash256 hash));
        Assert.AreEqual(default, hash);
        AssertVerified(leaf, 0, [zeroHashNode], root);
    }

    [TestMethod]
    [TestCategory("AllocationEvidence")]
    public void WarmValidVerificationDoesNotAllocate()
    {
        Hash256 leaf0 = Leaf(0);
        Hash256 leaf1 = Leaf(1);
        Hash256 root = Parent(leaf0, leaf1);
        ReadOnlySpan<MerkleBranchNode> branch = [new(leaf1)];
        for (var index = 0; index < 16; index++)
        {
            _ = MerkleInclusionVerifier.Verify(leaf0, 0, branch, root);
        }

        long before = GC.GetAllocatedBytesForCurrentThread();
        MerkleInclusionVerification result = default;
        for (var index = 0; index < 64; index++)
        {
            result = MerkleInclusionVerifier.Verify(leaf0, 0, branch, root);
        }

        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.AreEqual(0L, allocated);
        Assert.AreEqual(MerkleInclusionVerification.Verified, result);
    }

    private static void AssertVerified(
        Hash256 transactionId,
        ulong transactionIndex,
        ReadOnlySpan<MerkleBranchNode> branch,
        Hash256 expectedRoot) =>
        Assert.AreEqual(
            MerkleInclusionVerification.Verified,
            MerkleInclusionVerifier.Verify(
                transactionId,
                transactionIndex,
                branch,
                expectedRoot));

    private static Hash256 Leaf(byte value) => Hash256.DoubleSha256([value]);

    private static Hash256 FromWireHex(string wireHex)
    {
        byte[] wireBytes = Convert.FromHexString(wireHex);
        return FromWireBytes(wireBytes);
    }

    private static Hash256 FromWireBytes(ReadOnlySpan<byte> wireBytes)
    {
        Assert.AreEqual(
            System.Buffers.OperationStatus.Done,
            Hash256.TryCreate(wireBytes, out Hash256 hash));
        return hash;
    }

    private static byte[] CreateSequentialBytes(int start)
    {
        var bytes = new byte[Hash256.Length];
        for (var index = 0; index < bytes.Length; index++)
        {
            bytes[index] = checked((byte)(start + index));
        }

        return bytes;
    }

    private static Hash256 Parent(Hash256 left, Hash256 right)
    {
        Span<byte> pair = stackalloc byte[Hash256.Length * 2];
        left.WriteWireBytesTo(pair);
        right.WriteWireBytesTo(pair[Hash256.Length..]);
        return Hash256.DoubleSha256(pair);
    }
}
