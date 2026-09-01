using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Tests.Protocol.Blocks;

[TestClass]
public sealed class BsvMainnetContextualHeaderAdmissionTests
{
    private const string FixtureFileName = "headers-mainnet-daa-boundary-503885-504032-20260901.bin";
    private const int FirstFixtureHeight = 503_885;

    [TestMethod]
    public void BoundaryCandidateIsAdmittedAtomically()
    {
        BoundaryCase boundary = LoadBoundaryCase();

        ContextualHeaderAdmissionResult result = BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
            boundary.Parent,
            boundary.Context,
            boundary.Candidate);

        Assert.AreEqual(ContextualHeaderAdmissionStatus.Admitted, result.Status);
        Assert.IsTrue(result.TryGetAdmitted(out AdmittedBlockHeader admitted));
        Assert.AreEqual(504_032, admitted.Height);
        Assert.AreEqual(boundary.Candidate, admitted.Header);
        Assert.AreEqual(boundary.Candidate.ComputeHash(), admitted.Hash);
        Assert.AreEqual<uint>(0x1805b42b, admitted.Header.Bits);
        Assert.AreEqual(DifficultyAdjustmentCalculationStatus.Done, result.DifficultyCalculationStatus);
        Assert.AreEqual<uint?>(0x1805b42b, result.ExpectedCompactTarget);
        Assert.AreEqual<uint?>(0x1805b42b, result.ActualCompactTarget);
        Assert.AreEqual(
            boundary.Parent.CumulativeChainWork.Add(BlockProofOfWork.GetBlockWork(boundary.Candidate.Bits)),
            admitted.CumulativeChainWork);
    }

    [TestMethod]
    public void MissingContextIsRejectedWithoutExposingAdmission()
    {
        BoundaryCase boundary = LoadBoundaryCase();

        AssertRejected(
            BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
                boundary.Parent,
                boundary.Context.AsSpan(1),
                boundary.Candidate),
            ContextualHeaderAdmissionStatus.InvalidContextLength);
    }

    [TestMethod]
    public void ContextMustEndAtTheAuthoritativeParent()
    {
        BoundaryCase boundary = LoadBoundaryCase();
        BlockDifficultyContext[] context = (BlockDifficultyContext[])boundary.Context.Clone();
        context[^1] = context[^1] with { Timestamp = context[^1].Timestamp + 1 };

        AssertRejected(
            BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
                boundary.Parent,
                context,
                boundary.Candidate),
            ContextualHeaderAdmissionStatus.ContextDoesNotEndAtParent);
    }

    [TestMethod]
    public void ContextMustHaveConsecutiveHeightsAndIncreasingWork()
    {
        BoundaryCase boundary = LoadBoundaryCase();
        BlockDifficultyContext[] heightGap = (BlockDifficultyContext[])boundary.Context.Clone();
        heightGap[73] = heightGap[73] with { Height = heightGap[73].Height + 1 };
        BlockDifficultyContext[] repeatedWork = (BlockDifficultyContext[])boundary.Context.Clone();
        repeatedWork[73] = repeatedWork[73] with
        {
            CumulativeChainWork = repeatedWork[72].CumulativeChainWork,
        };

        AssertRejected(
            BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
                boundary.Parent,
                heightGap,
                boundary.Candidate),
            ContextualHeaderAdmissionStatus.NonConsecutiveContext);
        AssertRejected(
            BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
                boundary.Parent,
                repeatedWork,
                boundary.Candidate),
            ContextualHeaderAdmissionStatus.NonIncreasingContextWork);
    }

    [TestMethod]
    public void PreActivationParentIsRejectedAsInactive()
    {
        BoundaryCase boundary = LoadBoundaryCase();
        BlockDifficultyContext[] context = (BlockDifficultyContext[])boundary.Context.Clone();
        for (var index = 0; index < context.Length; index++)
        {
            context[index] = context[index] with { Height = context[index].Height - 1 };
        }

        AdmittedBlockHeader parent = boundary.Parent with { Height = boundary.Parent.Height - 1 };

        AssertRejected(
            BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
                parent,
                context,
                boundary.Candidate),
            ContextualHeaderAdmissionStatus.Inactive);
    }

    [TestMethod]
    public void CandidateMustLinkToTheAuthoritativeParent()
    {
        BoundaryCase boundary = LoadBoundaryCase();
        BlockHeader candidate = ReplaceCandidate(
            boundary.Candidate,
            previousBlockHash: default(Hash256));

        AssertRejected(
            BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
                boundary.Parent,
                boundary.Context,
                candidate),
            ContextualHeaderAdmissionStatus.PreviousBlockHashMismatch);
    }

    [TestMethod]
    public void CandidateMustSatisfyItsClaimedProofOfWork()
    {
        BoundaryCase boundary = LoadBoundaryCase();
        BlockHeader candidate = ReplaceCandidate(
            boundary.Candidate,
            nonce: boundary.Candidate.Nonce + 1);

        ContextualHeaderAdmissionResult result = BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
            boundary.Parent,
            boundary.Context,
            candidate);

        AssertRejected(result, ContextualHeaderAdmissionStatus.InvalidProofOfWork);
        Assert.AreEqual(BlockProofOfWorkValidation.HashAboveTarget, result.ProofOfWorkValidation);
    }

    [TestMethod]
    public void CandidateTargetCannotExceedTheMainnetProofOfWorkLimit()
    {
        BoundaryCase boundary = LoadBoundaryCase();
        BlockHeader candidate = ReplaceCandidate(boundary.Candidate, bits: 0x1d010000);

        ContextualHeaderAdmissionResult result = BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
            boundary.Parent,
            boundary.Context,
            candidate);

        AssertRejected(result, ContextualHeaderAdmissionStatus.InvalidProofOfWork);
        Assert.AreEqual(BlockProofOfWorkValidation.TargetAboveLimit, result.ProofOfWorkValidation);
    }

    [TestMethod]
    public void CandidateBitsMustEqualTheContextualDaaResult()
    {
        BoundaryCase boundary = LoadBoundaryCase();
        BlockDifficultyContext[] context = (BlockDifficultyContext[])boundary.Context.Clone();
        for (var index = 0; index < 3; index++)
        {
            context[index] = context[index] with { Timestamp = context[index].Timestamp - 3_600 };
        }

        Assert.AreEqual(
            DifficultyAdjustmentCalculationStatus.Done,
            BsvMainnetDifficultyAdjustment.CalculateNextBits(
                context,
                CompactTarget.Decode(0x1d00ffff).Value,
                out uint changedBits));
        Assert.AreNotEqual(boundary.Candidate.Bits, changedBits);

        ContextualHeaderAdmissionResult result = BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
            boundary.Parent,
            context,
            boundary.Candidate);

        AssertRejected(result, ContextualHeaderAdmissionStatus.UnexpectedDifficulty);
        Assert.AreEqual(DifficultyAdjustmentCalculationStatus.Done, result.DifficultyCalculationStatus);
        Assert.AreEqual<uint?>(changedBits, result.ExpectedCompactTarget);
        Assert.AreEqual<uint?>(boundary.Candidate.Bits, result.ActualCompactTarget);
    }

    [TestMethod]
    public void InvalidProofOfWorkWinsBeforeAConflictingDifficultyContext()
    {
        BoundaryCase boundary = LoadBoundaryCase();
        BlockDifficultyContext[] context = (BlockDifficultyContext[])boundary.Context.Clone();
        for (var index = 0; index < 3; index++)
        {
            context[index] = context[index] with { Timestamp = context[index].Timestamp - 3_600 };
        }

        BlockHeader candidate = ReplaceCandidate(
            boundary.Candidate,
            nonce: boundary.Candidate.Nonce + 1);

        ContextualHeaderAdmissionResult result =
            BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
                boundary.Parent,
                context,
                candidate);

        AssertRejected(result, ContextualHeaderAdmissionStatus.InvalidProofOfWork);
        Assert.AreEqual(BlockProofOfWorkValidation.HashAboveTarget, result.ProofOfWorkValidation);
        Assert.IsNull(result.DifficultyCalculationStatus);
        Assert.IsNull(result.ExpectedCompactTarget);
        Assert.IsNull(result.ActualCompactTarget);
    }

    [TestMethod]
    public void DifficultyCalculationFailureRetainsItsNestedEvidence()
    {
        BoundaryCase boundary = LoadBoundaryCase();
        BlockDifficultyContext[] context = (BlockDifficultyContext[])boundary.Context.Clone();
        for (var index = 0; index < context.Length; index++)
        {
            context[index] = context[index] with
            {
                Timestamp = index < 3 ? context[index].Timestamp - 100_000 : context[index].Timestamp,
                CumulativeChainWork = UInt256.FromUInt64((ulong)index + 1),
            };
        }

        AdmittedBlockHeader parent = boundary.Parent with
        {
            CumulativeChainWork = context[^1].CumulativeChainWork,
        };

        ContextualHeaderAdmissionResult result = BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
            parent,
            context,
            boundary.Candidate);

        AssertRejected(result, ContextualHeaderAdmissionStatus.DifficultyCalculationFailed);
        Assert.AreEqual(
            DifficultyAdjustmentCalculationStatus.ZeroComputedWork,
            result.DifficultyCalculationStatus);
        Assert.IsNull(result.ExpectedCompactTarget);
        Assert.AreEqual<uint?>(boundary.Candidate.Bits, result.ActualCompactTarget);
    }

    [TestMethod]
    public void CumulativeWorkWrapIsRejectedWithoutExposingAdmission()
    {
        BoundaryCase boundary = LoadBoundaryCase();
        UInt256 candidateWork = BlockProofOfWork.GetBlockWork(boundary.Candidate.Bits);
        UInt256 wrappedParentWork = UInt256.MaxValue.Subtract(candidateWork).AddOne();
        UInt256 offset = wrappedParentWork.Subtract(boundary.Parent.CumulativeChainWork);
        BlockDifficultyContext[] context = (BlockDifficultyContext[])boundary.Context.Clone();
        for (var index = 0; index < context.Length; index++)
        {
            context[index] = context[index] with
            {
                CumulativeChainWork = context[index].CumulativeChainWork.Add(offset),
            };
        }

        AdmittedBlockHeader parent = boundary.Parent with
        {
            CumulativeChainWork = wrappedParentWork,
        };

        AssertRejected(
            BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
                parent,
                context,
                boundary.Candidate),
            ContextualHeaderAdmissionStatus.CumulativeChainWorkOverflow);
    }

    [TestMethod]
    public void DefaultResultDoesNotExposeAnAdmittedHeader()
    {
        var result = default(ContextualHeaderAdmissionResult);

        Assert.AreEqual(ContextualHeaderAdmissionStatus.Uninitialized, result.Status);
        Assert.IsFalse(result.TryGetAdmitted(out _));
    }

    [TestMethod]
    public void MaximumParentHeightIsRejectedWithoutWrappingTheCandidateHeight()
    {
        BoundaryCase boundary = LoadBoundaryCase();
        BlockDifficultyContext[] context = (BlockDifficultyContext[])boundary.Context.Clone();
        int firstHeight = int.MaxValue - context.Length + 1;
        for (var index = 0; index < context.Length; index++)
        {
            context[index] = context[index] with { Height = firstHeight + index };
        }

        AdmittedBlockHeader parent = boundary.Parent with { Height = int.MaxValue };

        AssertRejected(
            BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
                parent,
                context,
                boundary.Candidate),
            ContextualHeaderAdmissionStatus.HeightOverflow);
    }

    [TestMethod]
    [TestCategory("AllocationEvidence")]
    public void ValidAdmissionDoesNotAllocateAfterWarmup()
    {
        BoundaryCase boundary = LoadBoundaryCase();
        for (var index = 0; index < 16; index++)
        {
            _ = BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
                boundary.Parent,
                boundary.Context,
                boundary.Candidate);
        }

        long before = GC.GetAllocatedBytesForCurrentThread();
        ContextualHeaderAdmissionResult result = default;
        for (var index = 0; index < 32; index++)
        {
            result = BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
                boundary.Parent,
                boundary.Context,
                boundary.Candidate);
        }

        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.AreEqual(0L, allocated);
        Assert.IsTrue(result.TryGetAdmitted(out _));
    }

    private static void AssertRejected(
        ContextualHeaderAdmissionResult result,
        ContextualHeaderAdmissionStatus expectedStatus)
    {
        Assert.AreEqual(expectedStatus, result.Status);
        Assert.IsFalse(result.TryGetAdmitted(out AdmittedBlockHeader admitted));
        Assert.AreEqual(default, admitted);
    }

    private static BoundaryCase LoadBoundaryCase()
    {
        byte[] payload = File.ReadAllBytes(GetFixturePath(FixtureFileName));
        var headers = new BlockHeader[148];
        Assert.AreEqual(
            OperationStatus.Done,
            HeadersPayloadCodec.TryParse(payload, headers, out int headerCount));
        Assert.AreEqual(headers.Length, headerCount);

        var context = new BlockDifficultyContext[BsvMainnetDifficultyAdjustment.RequiredContextLength];
        UInt256 cumulativeWork = UInt256.Zero;
        for (var index = 0; index < context.Length; index++)
        {
            cumulativeWork = cumulativeWork.Add(BlockProofOfWork.GetBlockWork(headers[index].Bits));
            context[index] = new BlockDifficultyContext(
                FirstFixtureHeight + index,
                headers[index].Timestamp,
                cumulativeWork);
        }

        BlockHeader parentHeader = headers[context.Length - 1];
        var parent = new AdmittedBlockHeader(
            parentHeader,
            parentHeader.ComputeHash(),
            504_031,
            cumulativeWork);
        return new BoundaryCase(parent, context, headers[^1]);
    }

    private static BlockHeader ReplaceCandidate(
        in BlockHeader source,
        Hash256? previousBlockHash = null,
        uint? bits = null,
        uint? nonce = null) =>
        new(
            source.Version,
            previousBlockHash ?? source.PreviousBlockHash,
            source.MerkleRoot,
            source.Timestamp,
            bits ?? source.Bits,
            nonce ?? source.Nonce);

    private static string GetFixturePath(string fileName) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "Bsv", fileName);

    private sealed record BoundaryCase(
        AdmittedBlockHeader Parent,
        BlockDifficultyContext[] Context,
        BlockHeader Candidate);
}
