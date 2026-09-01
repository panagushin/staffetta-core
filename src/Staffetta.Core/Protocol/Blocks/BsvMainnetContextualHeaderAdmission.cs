using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

internal enum ContextualHeaderAdmissionStatus
{
    Uninitialized,
    Admitted,
    Inactive,
    InvalidContextLength,
    ContextDoesNotEndAtParent,
    NonConsecutiveContext,
    NonIncreasingContextWork,
    PreviousBlockHashMismatch,
    InvalidProofOfWork,
    DifficultyCalculationFailed,
    UnexpectedDifficulty,
    CumulativeChainWorkOverflow,
    HeightOverflow,
}

internal readonly struct ContextualHeaderAdmissionResult
{
    private readonly AdmittedBlockHeader _admittedHeader;
    private readonly bool _hasAdmittedHeader;

    private ContextualHeaderAdmissionResult(
        ContextualHeaderAdmissionStatus status,
        BlockProofOfWorkValidation? proofOfWorkValidation,
        DifficultyAdjustmentCalculationStatus? difficultyCalculationStatus,
        uint? expectedCompactTarget,
        uint? actualCompactTarget,
        AdmittedBlockHeader admittedHeader,
        bool hasAdmittedHeader)
    {
        Status = status;
        ProofOfWorkValidation = proofOfWorkValidation;
        DifficultyCalculationStatus = difficultyCalculationStatus;
        ExpectedCompactTarget = expectedCompactTarget;
        ActualCompactTarget = actualCompactTarget;
        _admittedHeader = admittedHeader;
        _hasAdmittedHeader = hasAdmittedHeader;
    }

    internal ContextualHeaderAdmissionStatus Status { get; }

    internal BlockProofOfWorkValidation? ProofOfWorkValidation { get; }

    internal DifficultyAdjustmentCalculationStatus? DifficultyCalculationStatus { get; }

    internal uint? ExpectedCompactTarget { get; }

    internal uint? ActualCompactTarget { get; }

    internal bool TryGetAdmitted(out AdmittedBlockHeader admittedHeader)
    {
        admittedHeader = _hasAdmittedHeader ? _admittedHeader : default;
        return _hasAdmittedHeader;
    }

    internal static ContextualHeaderAdmissionResult Rejected(
        ContextualHeaderAdmissionStatus status,
        BlockProofOfWorkValidation? proofOfWorkValidation = null,
        DifficultyAdjustmentCalculationStatus? difficultyCalculationStatus = null,
        uint? expectedCompactTarget = null,
        uint? actualCompactTarget = null) =>
        new(
            status,
            proofOfWorkValidation,
            difficultyCalculationStatus,
            expectedCompactTarget,
            actualCompactTarget,
            default,
            hasAdmittedHeader: false);

    internal static ContextualHeaderAdmissionResult Accepted(
        AdmittedBlockHeader admittedHeader,
        uint expectedCompactTarget,
        uint actualCompactTarget) =>
        new(
            ContextualHeaderAdmissionStatus.Admitted,
            BlockProofOfWorkValidation.Valid,
            DifficultyAdjustmentCalculationStatus.Done,
            expectedCompactTarget,
            actualCompactTarget,
            admittedHeader,
            hasAdmittedHeader: true);
}

internal static class BsvMainnetContextualHeaderAdmission
{
    private static readonly UInt256 MainnetProofOfWorkLimit = CompactTarget.Decode(0x1d00ffff).Value;

    // The context is a projection of already-admitted ancestry owned by the chain authority.
    // Its scalar values cannot establish branch identity, so untrusted peer data must never be passed here.
    internal static ContextualHeaderAdmissionResult AdmitFromAuthoritativeContext(
        in AdmittedBlockHeader parent,
        ReadOnlySpan<BlockDifficultyContext> authoritativeContext,
        in BlockHeader candidate)
    {
        if (authoritativeContext.Length != BsvMainnetDifficultyAdjustment.RequiredContextLength)
        {
            return ContextualHeaderAdmissionResult.Rejected(
                ContextualHeaderAdmissionStatus.InvalidContextLength);
        }

        BlockDifficultyContext contextParent = authoritativeContext[^1];
        if (contextParent.Height != parent.Height ||
            contextParent.Timestamp != parent.Header.Timestamp ||
            contextParent.CumulativeChainWork != parent.CumulativeChainWork)
        {
            return ContextualHeaderAdmissionResult.Rejected(
                ContextualHeaderAdmissionStatus.ContextDoesNotEndAtParent);
        }

        for (var index = 1; index < authoritativeContext.Length; index++)
        {
            if (authoritativeContext[index].Height != authoritativeContext[index - 1].Height + 1)
            {
                return ContextualHeaderAdmissionResult.Rejected(
                    ContextualHeaderAdmissionStatus.NonConsecutiveContext);
            }

            if (authoritativeContext[index].CumulativeChainWork <=
                authoritativeContext[index - 1].CumulativeChainWork)
            {
                return ContextualHeaderAdmissionResult.Rejected(
                    ContextualHeaderAdmissionStatus.NonIncreasingContextWork);
            }
        }

        if (parent.Height < BsvMainnetDifficultyAdjustment.ActivationPreviousHeight)
        {
            return ContextualHeaderAdmissionResult.Rejected(ContextualHeaderAdmissionStatus.Inactive);
        }

        if (parent.Height == int.MaxValue)
        {
            return ContextualHeaderAdmissionResult.Rejected(ContextualHeaderAdmissionStatus.HeightOverflow);
        }

        if (candidate.PreviousBlockHash != parent.Hash)
        {
            return ContextualHeaderAdmissionResult.Rejected(
                ContextualHeaderAdmissionStatus.PreviousBlockHashMismatch);
        }

        Hash256 candidateHash = candidate.ComputeHash();
        BlockProofOfWorkValidation proofOfWork = BlockProofOfWork.Validate(
            candidateHash,
            candidate.Bits,
            MainnetProofOfWorkLimit);
        if (proofOfWork != BlockProofOfWorkValidation.Valid)
        {
            return ContextualHeaderAdmissionResult.Rejected(
                ContextualHeaderAdmissionStatus.InvalidProofOfWork,
                proofOfWork);
        }

        DifficultyAdjustmentCalculationStatus calculationStatus =
            BsvMainnetDifficultyAdjustment.CalculateNextBits(
                authoritativeContext,
                MainnetProofOfWorkLimit,
                out uint expectedCompactTarget);
        if (calculationStatus != DifficultyAdjustmentCalculationStatus.Done)
        {
            return ContextualHeaderAdmissionResult.Rejected(
                ContextualHeaderAdmissionStatus.DifficultyCalculationFailed,
                difficultyCalculationStatus: calculationStatus,
                actualCompactTarget: candidate.Bits);
        }

        if (candidate.Bits != expectedCompactTarget)
        {
            return ContextualHeaderAdmissionResult.Rejected(
                ContextualHeaderAdmissionStatus.UnexpectedDifficulty,
                difficultyCalculationStatus: calculationStatus,
                expectedCompactTarget: expectedCompactTarget,
                actualCompactTarget: candidate.Bits);
        }

        UInt256 cumulativeChainWork = parent.CumulativeChainWork.Add(
            BlockProofOfWork.GetBlockWork(candidate.Bits));
        if (cumulativeChainWork <= parent.CumulativeChainWork)
        {
            return ContextualHeaderAdmissionResult.Rejected(
                ContextualHeaderAdmissionStatus.CumulativeChainWorkOverflow);
        }

        return ContextualHeaderAdmissionResult.Accepted(
            new AdmittedBlockHeader(
                candidate,
                candidateHash,
                parent.Height + 1,
                cumulativeChainWork),
            expectedCompactTarget,
            candidate.Bits);
    }
}
