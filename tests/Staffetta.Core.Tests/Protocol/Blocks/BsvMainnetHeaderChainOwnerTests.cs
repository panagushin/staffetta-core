using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Tests.Protocol.Blocks;

[TestClass]
public sealed class BsvMainnetHeaderChainOwnerTests
{
    private const string FixtureFileName = "headers-mainnet-daa-boundary-503885-504032-20260901.bin";
    private const int FirstFixtureHeight = 503_885;

    [TestMethod]
    public void BoundaryCandidateExtendsTheVerifiedBestChain()
    {
        BoundaryCase boundary = LoadBoundaryCase();
        BsvMainnetHeaderChainOwner owner = CreateOwner(boundary.Bootstrap);

        HeaderChainCandidateResult result = owner.Add(boundary.Candidate);

        Assert.AreEqual(HeaderChainCandidateStatus.Admitted, result.Status);
        Assert.IsTrue(result.TryGetAdmitted(out AdmittedBlockHeader admitted));
        Assert.AreEqual(504_032, admitted.Height);
        Assert.AreEqual(boundary.Candidate.ComputeHash(), admitted.Hash);
        Assert.AreEqual(admitted, owner.BestTip);
        Assert.AreEqual(BestChainProjectionChangeKind.Extended, result.ProjectionChange.Kind);
        Assert.AreEqual(boundary.Bootstrap[^1], result.ProjectionChange.PreviousTip);
        Assert.AreEqual(admitted, result.ProjectionChange.CurrentTip);
        Assert.AreEqual(boundary.Bootstrap[^1], result.ProjectionChange.CommonAncestor);
        Assert.AreEqual(0, result.ProjectionChange.Detached.Length);
        CollectionAssert.AreEqual(
            new[] { admitted },
            result.ProjectionChange.Attached.ToArray());
    }

    [TestMethod]
    public void RejectedAndDuplicateCandidatesNeverChangeTheBestTip()
    {
        BoundaryCase boundary = LoadBoundaryCase();
        BsvMainnetHeaderChainOwner owner = CreateOwner(boundary.Bootstrap);
        AdmittedBlockHeader originalTip = owner.BestTip;
        BlockHeader invalidProofOfWork = ReplaceHeader(
            boundary.Candidate,
            nonce: boundary.Candidate.Nonce + 1);
        var unknownParent = new BlockHeader(
            boundary.Candidate.Version,
            default,
            boundary.Candidate.MerkleRoot,
            boundary.Candidate.Timestamp,
            boundary.Candidate.Bits,
            boundary.Candidate.Nonce);
        var insufficientAncestry = new BlockHeader(
            boundary.Candidate.Version,
            boundary.Bootstrap[0].Hash,
            boundary.Candidate.MerkleRoot,
            boundary.Candidate.Timestamp,
            boundary.Candidate.Bits,
            boundary.Candidate.Nonce);

        HeaderChainCandidateResult consensusRejected = owner.Add(invalidProofOfWork);
        Assert.AreEqual(HeaderChainCandidateStatus.ConsensusRejected, consensusRejected.Status);
        Assert.AreEqual(ContextualHeaderAdmissionStatus.InvalidProofOfWork, consensusRejected.Admission.Status);
        Assert.IsFalse(consensusRejected.TryGetAdmitted(out _));
        Assert.AreEqual(originalTip, owner.BestTip);

        HeaderChainCandidateResult unknown = owner.Add(unknownParent);
        Assert.AreEqual(HeaderChainCandidateStatus.UnknownParent, unknown.Status);
        Assert.IsFalse(unknown.TryGetAdmitted(out _));
        Assert.AreEqual(originalTip, owner.BestTip);

        HeaderChainCandidateResult insufficient = owner.Add(insufficientAncestry);
        Assert.AreEqual(HeaderChainCandidateStatus.InsufficientAncestry, insufficient.Status);
        Assert.IsFalse(insufficient.TryGetAdmitted(out _));
        Assert.AreEqual(originalTip, owner.BestTip);

        HeaderChainCandidateResult earlyBootstrapDuplicate = owner.Add(boundary.Bootstrap[1].Header);
        Assert.AreEqual(HeaderChainCandidateStatus.Duplicate, earlyBootstrapDuplicate.Status);
        Assert.IsFalse(earlyBootstrapDuplicate.TryGetAdmitted(out _));
        Assert.AreEqual(originalTip, owner.BestTip);

        HeaderChainCandidateResult accepted = owner.Add(boundary.Candidate);
        Assert.AreEqual(HeaderChainCandidateStatus.Admitted, accepted.Status);
        AdmittedBlockHeader acceptedTip = owner.BestTip;

        HeaderChainCandidateResult duplicate = owner.Add(boundary.Candidate);
        Assert.AreEqual(HeaderChainCandidateStatus.Duplicate, duplicate.Status);
        Assert.IsFalse(duplicate.TryGetAdmitted(out _));
        Assert.AreEqual(acceptedTip, owner.BestTip);
    }

    [TestMethod]
    public void BootstrapRejectsEveryLocallyProvableAuthorityViolation()
    {
        BoundaryCase boundary = LoadBoundaryCase();

        AssertBootstrapRejected(
            boundary.Bootstrap.AsSpan(1),
            HeaderChainBootstrapStatus.InsufficientHistory);

        AdmittedBlockHeader[] hashMismatch = Clone(boundary.Bootstrap);
        hashMismatch[73] = hashMismatch[73] with { Hash = default };
        AssertBootstrapRejected(hashMismatch, HeaderChainBootstrapStatus.HashMismatch);

        AdmittedBlockHeader[] duplicate = Clone(boundary.Bootstrap);
        duplicate[73] = duplicate[72];
        AssertBootstrapRejected(duplicate, HeaderChainBootstrapStatus.DuplicateHash);

        AdmittedBlockHeader[] brokenLinkage = Clone(boundary.Bootstrap);
        BlockHeader unlinked = ReplaceHeader(brokenLinkage[73].Header, previousBlockHash: default(Hash256));
        brokenLinkage[73] = brokenLinkage[73] with
        {
            Header = unlinked,
            Hash = unlinked.ComputeHash(),
        };
        AssertBootstrapRejected(brokenLinkage, HeaderChainBootstrapStatus.BrokenLinkage);

        AdmittedBlockHeader[] heightGap = Clone(boundary.Bootstrap);
        heightGap[73] = heightGap[73] with { Height = heightGap[73].Height + 1 };
        AssertBootstrapRejected(heightGap, HeaderChainBootstrapStatus.NonConsecutiveHeight);

        AdmittedBlockHeader[] wrongWork = Clone(boundary.Bootstrap);
        wrongWork[73] = wrongWork[73] with
        {
            CumulativeChainWork = wrongWork[73].CumulativeChainWork.AddOne(),
        };
        AssertBootstrapRejected(wrongWork, HeaderChainBootstrapStatus.InvalidCumulativeChainWork);

        AdmittedBlockHeader[] invalidProofOfWork = Clone(boundary.Bootstrap);
        BlockHeader unmined = ReplaceHeader(
            invalidProofOfWork[73].Header,
            nonce: invalidProofOfWork[73].Header.Nonce + 1);
        invalidProofOfWork[73] = invalidProofOfWork[73] with
        {
            Header = unmined,
            Hash = unmined.ComputeHash(),
        };
        HeaderChainBootstrapResult invalidProofResult =
            BsvMainnetHeaderChainOwner.CreateFromTrustedBootstrap(invalidProofOfWork);
        Assert.AreEqual(HeaderChainBootstrapStatus.InvalidProofOfWork, invalidProofResult.Status);
        Assert.AreEqual(BlockProofOfWorkValidation.HashAboveTarget, invalidProofResult.ProofOfWorkValidation);
        Assert.IsFalse(invalidProofResult.TryGetOwner(out _));

        AdmittedBlockHeader[] inactive = Clone(boundary.Bootstrap);
        for (var index = 0; index < inactive.Length; index++)
        {
            inactive[index] = inactive[index] with { Height = inactive[index].Height - 1 };
        }

        AssertBootstrapRejected(inactive, HeaderChainBootstrapStatus.Inactive);
    }

    [TestMethod]
    public void ParentLocalWindowsDivergeAcrossCompetingBranches()
    {
        AdmittedBlockHeader[] bootstrap = CreateSyntheticBootstrap();
        AdmittedHeaderChain chain = AdmittedHeaderChain.CreateFromValidatedBootstrap(bootstrap);
        AdmittedBlockHeader fork = chain.BestTip;
        AdmittedBlockHeader firstBranch = CreateSyntheticChild(fork, timestamp: 2_000_000, nonce: 1);
        AdmittedBlockHeader secondBranch = CreateSyntheticChild(fork, timestamp: 3_000_000, nonce: 2);
        Assert.AreEqual(AdmittedHeaderCommitStatus.Committed, chain.Commit(firstBranch).Status);
        Assert.AreEqual(AdmittedHeaderCommitStatus.Committed, chain.Commit(secondBranch).Status);

        Span<BlockDifficultyContext> firstContext =
            stackalloc BlockDifficultyContext[BsvMainnetDifficultyAdjustment.RequiredContextLength];
        Span<BlockDifficultyContext> secondContext =
            stackalloc BlockDifficultyContext[BsvMainnetDifficultyAdjustment.RequiredContextLength];

        Assert.IsTrue(chain.TryBuildDifficultyContext(firstBranch.Hash, firstContext));
        Assert.IsTrue(chain.TryBuildDifficultyContext(secondBranch.Hash, secondContext));
        Assert.AreEqual(firstBranch.Header.Timestamp, firstContext[^1].Timestamp);
        Assert.AreEqual(secondBranch.Header.Timestamp, secondContext[^1].Timestamp);
        Assert.AreNotEqual(firstContext[^1].Timestamp, secondContext[^1].Timestamp);
        Assert.AreEqual(fork.Header.Timestamp, firstContext[^2].Timestamp);
        Assert.AreEqual(fork.Header.Timestamp, secondContext[^2].Timestamp);
    }

    [TestMethod]
    public void TopologyRejectsInvalidAdmittedEvidenceBeforeMutation()
    {
        AdmittedBlockHeader[] bootstrap = CreateSyntheticBootstrap();
        AdmittedHeaderChain chain = AdmittedHeaderChain.CreateFromValidatedBootstrap(bootstrap);
        AdmittedBlockHeader originalTip = chain.BestTip;

        AdmittedHeaderCommitResult duplicate = chain.Commit(originalTip);
        Assert.AreEqual(AdmittedHeaderCommitStatus.Duplicate, duplicate.Status);
        Assert.AreEqual(originalTip, chain.BestTip);

        AdmittedBlockHeader unknownParent = CreateSyntheticChild(
            originalTip,
            timestamp: 2_000_000,
            nonce: 5);
        BlockHeader unlinkedHeader = ReplaceHeader(unknownParent.Header, previousBlockHash: default(Hash256));
        unknownParent = unknownParent with
        {
            Header = unlinkedHeader,
            Hash = unlinkedHeader.ComputeHash(),
        };
        AdmittedHeaderCommitResult unknown = chain.Commit(unknownParent);
        Assert.AreEqual(AdmittedHeaderCommitStatus.UnknownParent, unknown.Status);
        Assert.IsFalse(chain.Contains(unknownParent.Hash));
        Assert.AreEqual(originalTip, chain.BestTip);

        AdmittedBlockHeader invalidHeight = CreateSyntheticChild(
            originalTip,
            timestamp: 2_000_600,
            nonce: 6) with
        {
            Height = originalTip.Height + 2,
        };
        AdmittedHeaderCommitResult height = chain.Commit(invalidHeight);
        Assert.AreEqual(AdmittedHeaderCommitStatus.InvalidHeight, height.Status);
        Assert.IsFalse(chain.Contains(invalidHeight.Hash));
        Assert.AreEqual(originalTip, chain.BestTip);

        AdmittedBlockHeader invalidWork = CreateSyntheticChild(
            originalTip,
            timestamp: 2_001_200,
            nonce: 7);
        invalidWork = invalidWork with
        {
            CumulativeChainWork = invalidWork.CumulativeChainWork.AddOne(),
        };
        AdmittedHeaderCommitResult work = chain.Commit(invalidWork);
        Assert.AreEqual(AdmittedHeaderCommitStatus.InvalidCumulativeChainWork, work.Status);
        Assert.IsFalse(chain.Contains(invalidWork.Hash));
        Assert.AreEqual(originalTip, chain.BestTip);
    }

    [TestMethod]
    public void GreaterWorkRecomputesTheExactReorgProjectionAndTiesKeepTheIncumbent()
    {
        AdmittedBlockHeader[] bootstrap = CreateSyntheticBootstrap();
        AdmittedHeaderChain chain = AdmittedHeaderChain.CreateFromValidatedBootstrap(bootstrap);
        AdmittedBlockHeader fork = chain.BestTip;
        AdmittedBlockHeader firstA = CreateSyntheticChild(fork, timestamp: 2_000_000, nonce: 10);
        AdmittedHeaderCommitResult firstAResult = chain.Commit(firstA);
        Assert.AreEqual(BestChainProjectionChangeKind.Extended, firstAResult.ProjectionChange.Kind);

        AdmittedBlockHeader firstB = CreateSyntheticChild(fork, timestamp: 3_000_000, nonce: 20);
        AdmittedHeaderCommitResult tiedResult = chain.Commit(firstB);
        Assert.AreEqual(BestChainProjectionChangeKind.None, tiedResult.ProjectionChange.Kind);
        Assert.AreEqual(firstA, chain.BestTip);

        AdmittedBlockHeader secondB = CreateSyntheticChild(firstB, timestamp: 3_000_600, nonce: 21);
        AdmittedHeaderCommitResult reorg = chain.Commit(secondB);

        Assert.AreEqual(BestChainProjectionChangeKind.Reorganized, reorg.ProjectionChange.Kind);
        Assert.AreEqual(firstA, reorg.ProjectionChange.PreviousTip);
        Assert.AreEqual(secondB, reorg.ProjectionChange.CurrentTip);
        Assert.AreEqual(fork, reorg.ProjectionChange.CommonAncestor);
        CollectionAssert.AreEqual(
            new[] { firstA },
            reorg.ProjectionChange.Detached.ToArray());
        CollectionAssert.AreEqual(
            new[] { firstB, secondB },
            reorg.ProjectionChange.Attached.ToArray());
        Assert.AreEqual(secondB, chain.BestTip);

        AdmittedBlockHeader secondA = CreateSyntheticChild(firstA, timestamp: 2_000_600, nonce: 11);
        AdmittedHeaderCommitResult secondTie = chain.Commit(secondA);
        Assert.AreEqual(BestChainProjectionChangeKind.None, secondTie.ProjectionChange.Kind);
        Assert.AreEqual(secondB, chain.BestTip);

        AdmittedBlockHeader thirdA = CreateSyntheticChild(secondA, timestamp: 2_001_200, nonce: 12);
        AdmittedHeaderCommitResult reverseReorg = chain.Commit(thirdA);
        Assert.AreEqual(BestChainProjectionChangeKind.Reorganized, reverseReorg.ProjectionChange.Kind);
        Assert.AreEqual(fork, reverseReorg.ProjectionChange.CommonAncestor);
        CollectionAssert.AreEqual(
            new[] { secondB, firstB },
            reverseReorg.ProjectionChange.Detached.ToArray());
        CollectionAssert.AreEqual(
            new[] { firstA, secondA, thirdA },
            reverseReorg.ProjectionChange.Attached.ToArray());
        Assert.AreEqual(thirdA, chain.BestTip);
    }

    [TestMethod]
    public void ShorterBranchWithGreaterCumulativeWorkBecomesBest()
    {
        AdmittedBlockHeader[] bootstrap = CreateSyntheticBootstrap();
        AdmittedHeaderChain chain = AdmittedHeaderChain.CreateFromValidatedBootstrap(bootstrap);
        AdmittedBlockHeader fork = chain.BestTip;
        AdmittedBlockHeader firstLowWork = CreateSyntheticChild(
            fork,
            timestamp: 2_000_000,
            nonce: 30);
        AdmittedBlockHeader secondLowWork = CreateSyntheticChild(
            firstLowWork,
            timestamp: 2_000_600,
            nonce: 31);
        Assert.AreEqual(AdmittedHeaderCommitStatus.Committed, chain.Commit(firstLowWork).Status);
        Assert.AreEqual(AdmittedHeaderCommitStatus.Committed, chain.Commit(secondLowWork).Status);

        AdmittedBlockHeader shorterGreaterWork = CreateSyntheticChild(
            fork,
            timestamp: 3_000_000,
            nonce: 40,
            bits: 0x1f00ffff);
        Assert.IsTrue(shorterGreaterWork.Height < secondLowWork.Height);
        Assert.IsTrue(shorterGreaterWork.CumulativeChainWork > secondLowWork.CumulativeChainWork);

        AdmittedHeaderCommitResult reorg = chain.Commit(shorterGreaterWork);

        Assert.AreEqual(BestChainProjectionChangeKind.Reorganized, reorg.ProjectionChange.Kind);
        Assert.AreEqual(shorterGreaterWork, chain.BestTip);
        Assert.AreEqual(fork, reorg.ProjectionChange.CommonAncestor);
        CollectionAssert.AreEqual(
            new[] { secondLowWork, firstLowWork },
            reorg.ProjectionChange.Detached.ToArray());
        CollectionAssert.AreEqual(
            new[] { shorterGreaterWork },
            reorg.ProjectionChange.Attached.ToArray());
    }

    [TestMethod]
    [TestCategory("AllocationEvidence")]
    public void ParentLocalWindowAssemblyDoesNotAllocateAfterWarmup()
    {
        AdmittedBlockHeader[] bootstrap = CreateSyntheticBootstrap();
        AdmittedHeaderChain chain = AdmittedHeaderChain.CreateFromValidatedBootstrap(bootstrap);
        Span<BlockDifficultyContext> context =
            stackalloc BlockDifficultyContext[BsvMainnetDifficultyAdjustment.RequiredContextLength];
        for (var index = 0; index < 16; index++)
        {
            Assert.IsTrue(chain.TryBuildDifficultyContext(chain.BestTip.Hash, context));
        }

        long before = GC.GetAllocatedBytesForCurrentThread();
        for (var index = 0; index < 64; index++)
        {
            _ = chain.TryBuildDifficultyContext(chain.BestTip.Hash, context);
        }

        Assert.AreEqual(0L, GC.GetAllocatedBytesForCurrentThread() - before);
    }

    private static BsvMainnetHeaderChainOwner CreateOwner(AdmittedBlockHeader[] bootstrap)
    {
        HeaderChainBootstrapResult result =
            BsvMainnetHeaderChainOwner.CreateFromTrustedBootstrap(bootstrap);
        Assert.AreEqual(HeaderChainBootstrapStatus.Created, result.Status);
        Assert.IsTrue(result.TryGetOwner(out BsvMainnetHeaderChainOwner? owner));
        return owner!;
    }

    private static void AssertBootstrapRejected(
        ReadOnlySpan<AdmittedBlockHeader> bootstrap,
        HeaderChainBootstrapStatus expectedStatus)
    {
        HeaderChainBootstrapResult result =
            BsvMainnetHeaderChainOwner.CreateFromTrustedBootstrap(bootstrap);
        Assert.AreEqual(expectedStatus, result.Status);
        Assert.IsFalse(result.TryGetOwner(out _));
    }

    private static BoundaryCase LoadBoundaryCase()
    {
        byte[] payload = File.ReadAllBytes(GetFixturePath(FixtureFileName));
        var headers = new BlockHeader[148];
        Assert.AreEqual(
            OperationStatus.Done,
            HeadersPayloadCodec.TryParse(payload, headers, out int headerCount));
        Assert.AreEqual(headers.Length, headerCount);

        var bootstrap = new AdmittedBlockHeader[147];
        UInt256 cumulativeWork = UInt256.Zero;
        for (var index = 0; index < bootstrap.Length; index++)
        {
            cumulativeWork = cumulativeWork.Add(BlockProofOfWork.GetBlockWork(headers[index].Bits));
            bootstrap[index] = new AdmittedBlockHeader(
                headers[index],
                headers[index].ComputeHash(),
                FirstFixtureHeight + index,
                cumulativeWork);
        }

        return new BoundaryCase(bootstrap, headers[^1]);
    }

    private static AdmittedBlockHeader[] CreateSyntheticBootstrap()
    {
        var bootstrap = new AdmittedBlockHeader[BsvMainnetDifficultyAdjustment.RequiredContextLength];
        UInt256 cumulativeWork = UInt256.FromUInt64(1_000_000);
        Hash256 previousHash = default;
        for (var index = 0; index < bootstrap.Length; index++)
        {
            var header = new BlockHeader(
                1,
                previousHash,
                Hash256.DoubleSha256(BitConverter.GetBytes(index)),
                checked(1_000_000u + ((uint)index * 600)),
                0x207fffff,
                (uint)index);
            if (index > 0)
            {
                cumulativeWork = cumulativeWork.Add(BlockProofOfWork.GetBlockWork(header.Bits));
            }

            Hash256 hash = header.ComputeHash();
            bootstrap[index] = new AdmittedBlockHeader(
                header,
                hash,
                600_000 + index,
                cumulativeWork);
            previousHash = hash;
        }

        return bootstrap;
    }

    private static AdmittedBlockHeader CreateSyntheticChild(
        AdmittedBlockHeader parent,
        uint timestamp,
        uint nonce,
        uint bits = 0x207fffff)
    {
        var header = new BlockHeader(
            1,
            parent.Hash,
            Hash256.DoubleSha256(BitConverter.GetBytes(nonce)),
            timestamp,
            bits,
            nonce);
        return new AdmittedBlockHeader(
            header,
            header.ComputeHash(),
            parent.Height + 1,
            parent.CumulativeChainWork.Add(BlockProofOfWork.GetBlockWork(header.Bits)));
    }

    private static BlockHeader ReplaceHeader(
        in BlockHeader source,
        Hash256? previousBlockHash = null,
        uint? nonce = null) =>
        new(
            source.Version,
            previousBlockHash ?? source.PreviousBlockHash,
            source.MerkleRoot,
            source.Timestamp,
            source.Bits,
            nonce ?? source.Nonce);

    private static AdmittedBlockHeader[] Clone(AdmittedBlockHeader[] source) =>
        (AdmittedBlockHeader[])source.Clone();

    private static string GetFixturePath(string fileName) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "Bsv", fileName);

    private sealed record BoundaryCase(
        AdmittedBlockHeader[] Bootstrap,
        BlockHeader Candidate);
}
