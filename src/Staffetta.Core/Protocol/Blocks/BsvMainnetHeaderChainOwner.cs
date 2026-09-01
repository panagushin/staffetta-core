using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

internal enum HeaderChainBootstrapStatus
{
    Created,
    InsufficientHistory,
    HashMismatch,
    DuplicateHash,
    InvalidProofOfWork,
    BrokenLinkage,
    NonConsecutiveHeight,
    InvalidCumulativeChainWork,
    Inactive,
}

internal readonly struct HeaderChainBootstrapResult
{
    private readonly BsvMainnetHeaderChainOwner? _owner;

    private HeaderChainBootstrapResult(
        HeaderChainBootstrapStatus status,
        BlockProofOfWorkValidation? proofOfWorkValidation,
        BsvMainnetHeaderChainOwner? owner)
    {
        Status = status;
        ProofOfWorkValidation = proofOfWorkValidation;
        _owner = owner;
    }

    internal HeaderChainBootstrapStatus Status { get; }

    internal BlockProofOfWorkValidation? ProofOfWorkValidation { get; }

    internal bool TryGetOwner(out BsvMainnetHeaderChainOwner? owner)
    {
        owner = _owner;
        return owner is not null;
    }

    internal static HeaderChainBootstrapResult Rejected(
        HeaderChainBootstrapStatus status,
        BlockProofOfWorkValidation? proofOfWorkValidation = null) =>
        new(status, proofOfWorkValidation, owner: null);

    internal static HeaderChainBootstrapResult Accepted(BsvMainnetHeaderChainOwner owner) =>
        new(HeaderChainBootstrapStatus.Created, BlockProofOfWorkValidation.Valid, owner);
}

internal enum HeaderChainCandidateStatus
{
    Admitted,
    Duplicate,
    UnknownParent,
    InsufficientAncestry,
    ConsensusRejected,
    AuthorityInvariantViolation,
}

internal readonly struct HeaderChainCandidateResult
{
    private readonly AdmittedBlockHeader _admittedHeader;
    private readonly bool _hasAdmittedHeader;

    private HeaderChainCandidateResult(
        HeaderChainCandidateStatus status,
        ContextualHeaderAdmissionResult admission,
        BestChainProjectionChange projectionChange,
        AdmittedBlockHeader admittedHeader,
        bool hasAdmittedHeader)
    {
        Status = status;
        Admission = admission;
        ProjectionChange = projectionChange;
        _admittedHeader = admittedHeader;
        _hasAdmittedHeader = hasAdmittedHeader;
    }

    internal HeaderChainCandidateStatus Status { get; }

    internal ContextualHeaderAdmissionResult Admission { get; }

    internal BestChainProjectionChange ProjectionChange { get; }

    internal bool TryGetAdmitted(out AdmittedBlockHeader admittedHeader)
    {
        admittedHeader = _hasAdmittedHeader ? _admittedHeader : default;
        return _hasAdmittedHeader;
    }

    internal static HeaderChainCandidateResult Rejected(
        HeaderChainCandidateStatus status,
        ContextualHeaderAdmissionResult admission = default) =>
        new(status, admission, default, default, hasAdmittedHeader: false);

    internal static HeaderChainCandidateResult Accepted(
        ContextualHeaderAdmissionResult admission,
        BestChainProjectionChange projectionChange,
        AdmittedBlockHeader admittedHeader) =>
        new(
            HeaderChainCandidateStatus.Admitted,
            admission,
            projectionChange,
            admittedHeader,
            hasAdmittedHeader: true);
}

internal sealed class BsvMainnetHeaderChainOwner
{
    private static readonly UInt256 MainnetProofOfWorkLimit = CompactTarget.Decode(0x1d00ffff).Value;
    private readonly AdmittedHeaderChain _chain;

    private BsvMainnetHeaderChainOwner(AdmittedHeaderChain chain)
    {
        _chain = chain;
    }

    internal AdmittedBlockHeader BestTip => _chain.BestTip;

    // Imported bootstrap evidence is a trust boundary. This verifies local consistency and claimed PoW,
    // but contextual DAA before the available ancestry remains a provenance-backed checkpoint claim.
    internal static HeaderChainBootstrapResult CreateFromTrustedBootstrap(
        ReadOnlySpan<AdmittedBlockHeader> trustedBootstrap)
    {
        if (trustedBootstrap.Length < BsvMainnetDifficultyAdjustment.RequiredContextLength)
        {
            return HeaderChainBootstrapResult.Rejected(
                HeaderChainBootstrapStatus.InsufficientHistory);
        }

        var hashes = new HashSet<Hash256>();
        for (var index = 0; index < trustedBootstrap.Length; index++)
        {
            AdmittedBlockHeader current = trustedBootstrap[index];
            if (current.Header.ComputeHash() != current.Hash)
            {
                return HeaderChainBootstrapResult.Rejected(HeaderChainBootstrapStatus.HashMismatch);
            }

            if (!hashes.Add(current.Hash))
            {
                return HeaderChainBootstrapResult.Rejected(HeaderChainBootstrapStatus.DuplicateHash);
            }

            if (index > 0)
            {
                AdmittedBlockHeader previous = trustedBootstrap[index - 1];
                if (current.Header.PreviousBlockHash != previous.Hash)
                {
                    return HeaderChainBootstrapResult.Rejected(HeaderChainBootstrapStatus.BrokenLinkage);
                }

                if (previous.Height == int.MaxValue || current.Height != previous.Height + 1)
                {
                    return HeaderChainBootstrapResult.Rejected(
                        HeaderChainBootstrapStatus.NonConsecutiveHeight);
                }

                UInt256 expectedChainWork = previous.CumulativeChainWork.Add(
                    BlockProofOfWork.GetBlockWork(current.Header.Bits));
                if (expectedChainWork <= previous.CumulativeChainWork ||
                    current.CumulativeChainWork != expectedChainWork)
                {
                    return HeaderChainBootstrapResult.Rejected(
                        HeaderChainBootstrapStatus.InvalidCumulativeChainWork);
                }
            }

            BlockProofOfWorkValidation proofOfWork = BlockProofOfWork.Validate(
                current.Hash,
                current.Header.Bits,
                MainnetProofOfWorkLimit);
            if (proofOfWork != BlockProofOfWorkValidation.Valid)
            {
                return HeaderChainBootstrapResult.Rejected(
                    HeaderChainBootstrapStatus.InvalidProofOfWork,
                    proofOfWork);
            }
        }

        if (trustedBootstrap[^1].Height < BsvMainnetDifficultyAdjustment.ActivationPreviousHeight)
        {
            return HeaderChainBootstrapResult.Rejected(HeaderChainBootstrapStatus.Inactive);
        }

        return HeaderChainBootstrapResult.Accepted(
            new BsvMainnetHeaderChainOwner(
                AdmittedHeaderChain.CreateFromValidatedBootstrap(trustedBootstrap)));
    }

    internal HeaderChainCandidateResult Add(in BlockHeader candidate)
    {
        if (!_chain.TryGet(candidate.PreviousBlockHash, out AdmittedBlockHeader parent))
        {
            Hash256 candidateHash = candidate.ComputeHash();
            return HeaderChainCandidateResult.Rejected(
                _chain.Contains(candidateHash)
                    ? HeaderChainCandidateStatus.Duplicate
                    : HeaderChainCandidateStatus.UnknownParent);
        }

        Span<BlockDifficultyContext> authoritativeContext =
            stackalloc BlockDifficultyContext[BsvMainnetDifficultyAdjustment.RequiredContextLength];
        if (!_chain.TryBuildDifficultyContext(parent.Hash, authoritativeContext))
        {
            Hash256 candidateHash = candidate.ComputeHash();
            return HeaderChainCandidateResult.Rejected(
                _chain.Contains(candidateHash)
                    ? HeaderChainCandidateStatus.Duplicate
                    : HeaderChainCandidateStatus.InsufficientAncestry);
        }

        ContextualHeaderAdmissionResult admission =
            BsvMainnetContextualHeaderAdmission.AdmitFromAuthoritativeContext(
                parent,
                authoritativeContext,
                candidate);
        if (!admission.TryGetAdmitted(out AdmittedBlockHeader admitted))
        {
            return HeaderChainCandidateResult.Rejected(
                HeaderChainCandidateStatus.ConsensusRejected,
                admission);
        }

        AdmittedHeaderCommitResult commit = _chain.Commit(admitted);
        if (commit.Status == AdmittedHeaderCommitStatus.Duplicate)
        {
            return HeaderChainCandidateResult.Rejected(HeaderChainCandidateStatus.Duplicate);
        }

        if (commit.Status != AdmittedHeaderCommitStatus.Committed)
        {
            return HeaderChainCandidateResult.Rejected(
                HeaderChainCandidateStatus.AuthorityInvariantViolation,
                admission);
        }

        return HeaderChainCandidateResult.Accepted(
            admission,
            commit.ProjectionChange,
            admitted);
    }
}
