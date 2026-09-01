using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Tests.Protocol.Blocks;

[TestClass]
public sealed class CurrentSelectedChainInclusionTests
{
    [TestMethod]
    public void CurrentBestMembershipTracksExtensionTieAndReorg()
    {
        SyntheticOwner synthetic = CreateSyntheticOwner();
        Assert.IsTrue(synthetic.Chain.IsOnCurrentBestChain(synthetic.Fork.Hash));

        AdmittedBlockHeader firstA = CreateChild(synthetic.Fork, Leaf(1), nonce: 1);
        Assert.AreEqual(AdmittedHeaderCommitStatus.Committed, synthetic.Chain.Commit(firstA).Status);
        Assert.IsTrue(synthetic.Chain.IsOnCurrentBestChain(firstA.Hash));

        AdmittedBlockHeader firstB = CreateChild(synthetic.Fork, Leaf(2), nonce: 2);
        AdmittedHeaderCommitResult tie = synthetic.Chain.Commit(firstB);
        Assert.AreEqual(BestChainProjectionChangeKind.None, tie.ProjectionChange.Kind);
        Assert.IsTrue(synthetic.Chain.IsOnCurrentBestChain(firstA.Hash));
        Assert.IsFalse(synthetic.Chain.IsOnCurrentBestChain(firstB.Hash));

        AdmittedBlockHeader secondB = CreateChild(firstB, Leaf(3), nonce: 3);
        AdmittedHeaderCommitResult reorg = synthetic.Chain.Commit(secondB);
        Assert.AreEqual(BestChainProjectionChangeKind.Reorganized, reorg.ProjectionChange.Kind);
        Assert.IsTrue(synthetic.Chain.IsOnCurrentBestChain(synthetic.Fork.Hash));
        Assert.IsFalse(synthetic.Chain.IsOnCurrentBestChain(firstA.Hash));
        Assert.IsTrue(synthetic.Chain.IsOnCurrentBestChain(firstB.Hash));
        Assert.IsTrue(synthetic.Chain.IsOnCurrentBestChain(secondB.Hash));
        Assert.IsFalse(synthetic.Chain.IsOnCurrentBestChain(default));
    }

    [TestMethod]
    public void VerifiedEvidenceBindsTransactionBlockAndCurrentSelectedTip()
    {
        SyntheticOwner synthetic = CreateSyntheticOwner();
        Hash256 transactionId = Leaf(1);
        AdmittedBlockHeader included = CreateChild(synthetic.Fork, transactionId, nonce: 1);
        AdmittedBlockHeader tip = CreateChild(included, Leaf(2), nonce: 2);
        Assert.AreEqual(AdmittedHeaderCommitStatus.Committed, synthetic.Chain.Commit(included).Status);
        Assert.AreEqual(AdmittedHeaderCommitStatus.Committed, synthetic.Chain.Commit(tip).Status);

        CurrentSelectedChainInclusionResult result =
            synthetic.Owner.VerifyCurrentSelectedChainInclusion(
                transactionId,
                included.Hash,
                transactionIndex: 0,
                []);

        Assert.AreEqual(CurrentSelectedChainInclusionStatus.Verified, result.Status);
        Assert.AreEqual(MerkleInclusionVerification.Verified, result.ProofVerification);
        Assert.IsTrue(result.TryGetEvidence(out CurrentSelectedChainInclusionEvidence evidence));
        Assert.AreEqual(transactionId, evidence.TransactionId);
        Assert.AreEqual(included.Hash, evidence.BlockHash);
        Assert.AreEqual(included.Height, evidence.BlockHeight);
        Assert.AreEqual(included.Header.MerkleRoot, evidence.MerkleRoot);
        Assert.AreEqual(tip.Hash, evidence.SelectedTipHash);
        Assert.AreEqual(tip.Height, evidence.SelectedTipHeight);
        Assert.AreEqual(tip.CumulativeChainWork, evidence.SelectedTipCumulativeChainWork);
        Assert.AreEqual(2L, evidence.Confirmations);
    }

    [TestMethod]
    public void UnknownSideBranchAndInvalidProofRemainDistinct()
    {
        SyntheticOwner synthetic = CreateSyntheticOwner();
        Hash256 selectedTransactionId = Leaf(1);
        AdmittedBlockHeader selected = CreateChild(
            synthetic.Fork,
            selectedTransactionId,
            nonce: 1);
        Assert.AreEqual(AdmittedHeaderCommitStatus.Committed, synthetic.Chain.Commit(selected).Status);
        AdmittedBlockHeader side = CreateChild(synthetic.Fork, Leaf(2), nonce: 2);
        Assert.AreEqual(AdmittedHeaderCommitStatus.Committed, synthetic.Chain.Commit(side).Status);

        CurrentSelectedChainInclusionResult unknown =
            synthetic.Owner.VerifyCurrentSelectedChainInclusion(
                Leaf(3),
                default,
                transactionIndex: 0,
                []);
        Assert.AreEqual(CurrentSelectedChainInclusionStatus.UnknownAdmittedBlock, unknown.Status);
        Assert.AreEqual(MerkleInclusionVerification.NotEvaluated, unknown.ProofVerification);
        Assert.IsFalse(unknown.TryGetEvidence(out _));

        CurrentSelectedChainInclusionResult notSelected =
            synthetic.Owner.VerifyCurrentSelectedChainInclusion(
                side.Header.MerkleRoot,
                side.Hash,
                transactionIndex: 0,
                []);
        Assert.AreEqual(
            CurrentSelectedChainInclusionStatus.AdmittedBlockNotOnCurrentSelectedChain,
            notSelected.Status);
        Assert.AreEqual(MerkleInclusionVerification.NotEvaluated, notSelected.ProofVerification);
        Assert.IsFalse(notSelected.TryGetEvidence(out _));

        CurrentSelectedChainInclusionResult invalid =
            synthetic.Owner.VerifyCurrentSelectedChainInclusion(
                Leaf(9),
                selected.Hash,
                transactionIndex: 0,
                []);
        Assert.AreEqual(CurrentSelectedChainInclusionStatus.InvalidMerkleProof, invalid.Status);
        Assert.AreEqual(MerkleInclusionVerification.RootMismatch, invalid.ProofVerification);
        Assert.IsFalse(invalid.TryGetEvidence(out _));
    }

    [TestMethod]
    public void ReorgMakesPreviouslyVerifiedBlockNoLongerCurrentlySelected()
    {
        SyntheticOwner synthetic = CreateSyntheticOwner();
        Hash256 transactionId = Leaf(1);
        AdmittedBlockHeader firstA = CreateChild(synthetic.Fork, transactionId, nonce: 1);
        Assert.AreEqual(AdmittedHeaderCommitStatus.Committed, synthetic.Chain.Commit(firstA).Status);

        CurrentSelectedChainInclusionResult before =
            synthetic.Owner.VerifyCurrentSelectedChainInclusion(
                transactionId,
                firstA.Hash,
                transactionIndex: 0,
                []);
        Assert.AreEqual(CurrentSelectedChainInclusionStatus.Verified, before.Status);

        AdmittedBlockHeader firstB = CreateChild(synthetic.Fork, Leaf(2), nonce: 2);
        AdmittedBlockHeader secondB = CreateChild(firstB, Leaf(3), nonce: 3);
        Assert.AreEqual(AdmittedHeaderCommitStatus.Committed, synthetic.Chain.Commit(firstB).Status);
        AdmittedHeaderCommitResult reorg = synthetic.Chain.Commit(secondB);
        Assert.AreEqual(BestChainProjectionChangeKind.Reorganized, reorg.ProjectionChange.Kind);

        CurrentSelectedChainInclusionResult after =
            synthetic.Owner.VerifyCurrentSelectedChainInclusion(
                transactionId,
                firstA.Hash,
                transactionIndex: 0,
                []);
        Assert.AreEqual(
            CurrentSelectedChainInclusionStatus.AdmittedBlockNotOnCurrentSelectedChain,
            after.Status);
        Assert.AreEqual(MerkleInclusionVerification.NotEvaluated, after.ProofVerification);
        Assert.IsFalse(after.TryGetEvidence(out _));
    }

    [TestMethod]
    [TestCategory("AllocationEvidence")]
    public void WarmVerifiedOwnerProjectionDoesNotAllocate()
    {
        SyntheticOwner synthetic = CreateSyntheticOwner();
        Hash256 transactionId = Leaf(1);
        AdmittedBlockHeader included = CreateChild(synthetic.Fork, transactionId, nonce: 1);
        Assert.AreEqual(AdmittedHeaderCommitStatus.Committed, synthetic.Chain.Commit(included).Status);
        for (var index = 0; index < 16; index++)
        {
            _ = synthetic.Owner.VerifyCurrentSelectedChainInclusion(
                transactionId,
                included.Hash,
                transactionIndex: 0,
                []);
        }

        long before = GC.GetAllocatedBytesForCurrentThread();
        CurrentSelectedChainInclusionResult result = default;
        for (var index = 0; index < 64; index++)
        {
            result = synthetic.Owner.VerifyCurrentSelectedChainInclusion(
                transactionId,
                included.Hash,
                transactionIndex: 0,
                []);
        }

        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.AreEqual(0L, allocated);
        Assert.AreEqual(CurrentSelectedChainInclusionStatus.Verified, result.Status);
    }

    private static SyntheticOwner CreateSyntheticOwner()
    {
        Hash256 root = Leaf(0);
        var header = new BlockHeader(1, default, root, 1_000_000, 0x207fffff, 0);
        var fork = new AdmittedBlockHeader(
            header,
            header.ComputeHash(),
            600_000,
            UInt256.FromUInt64(1_000_000));
        AdmittedHeaderChain chain =
            AdmittedHeaderChain.CreateFromValidatedBootstrap([fork]);
        ConstructorInfo constructor = typeof(BsvMainnetHeaderChainOwner).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            [typeof(AdmittedHeaderChain)],
            modifiers: null) ?? throw new InvalidOperationException("Owner constructor not found.");
        var owner = (BsvMainnetHeaderChainOwner)constructor.Invoke([chain]);
        return new SyntheticOwner(chain, owner, fork);
    }

    private static AdmittedBlockHeader CreateChild(
        AdmittedBlockHeader parent,
        Hash256 merkleRoot,
        uint nonce)
    {
        var header = new BlockHeader(
            1,
            parent.Hash,
            merkleRoot,
            parent.Header.Timestamp + 600,
            0x207fffff,
            nonce);
        return new AdmittedBlockHeader(
            header,
            header.ComputeHash(),
            parent.Height + 1,
            parent.CumulativeChainWork.Add(BlockProofOfWork.GetBlockWork(header.Bits)));
    }

    private static Hash256 Leaf(byte value) => Hash256.DoubleSha256([value]);

    private sealed record SyntheticOwner(
        AdmittedHeaderChain Chain,
        BsvMainnetHeaderChainOwner Owner,
        AdmittedBlockHeader Fork);
}
