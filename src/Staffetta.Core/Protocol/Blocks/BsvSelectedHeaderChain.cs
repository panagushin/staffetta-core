using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

/// <summary>A header checkpoint value, not an independently authenticated authority.</summary>
/// <param name="Header">Serialized header fields.</param>
/// <param name="Hash">Claimed header hash, checked when importing trusted bootstrap.</param>
/// <param name="Height">Claimed height, anchored by caller-trusted bootstrap provenance.</param>
/// <param name="CumulativeChainWork">Claimed cumulative work; its initial offset remains trusted bootstrap metadata.</param>
public readonly record struct BsvHeaderCheckpoint(BlockHeader Header, Hash256 Hash, int Height, BigInteger CumulativeChainWork);

/// <summary>Outcome of submitting a peer header to contextual selected-chain admission.</summary>
public enum BsvHeaderCandidateStatus
{
    /// <summary>The candidate was contextually admitted; it may or may not change the selected tip.</summary>
    Admitted,
    /// <summary>The header is already known.</summary>
    Duplicate,
    /// <summary>The parent is not retained by this authority.</summary>
    UnknownParent,
    /// <summary>The retained branch lacks enough authoritative DAA ancestry.</summary>
    InsufficientAncestry,
    /// <summary>Proof of work or contextual mainnet difficulty admission failed.</summary>
    ConsensusRejected,
    /// <summary>An internal authority invariant prevented commitment.</summary>
    AuthorityInvariantViolation,
}

/// <summary>A selected-chain change caused by one contextually admitted header.</summary>
public sealed class BsvHeaderSelectionChange
{
    internal BsvHeaderSelectionChange(BestChainProjectionChange change)
    {
        PreviousTip = BsvSelectedHeaderChain.Export(change.PreviousTip);
        SelectedTip = BsvSelectedHeaderChain.Export(change.CurrentTip);
        CommonAncestor = change.CommonAncestor is { } ancestor ? BsvSelectedHeaderChain.Export(ancestor) : null;
        IsReorganization = change.Kind == BestChainProjectionChangeKind.Reorganized;
        Detached = ExportHeaders(change.Detached.Span);
        Attached = ExportHeaders(change.Attached.Span);
    }

    /// <summary>Gets the former selected tip.</summary>
    public BsvHeaderCheckpoint PreviousTip { get; }
    /// <summary>Gets the selected tip after admission.</summary>
    public BsvHeaderCheckpoint SelectedTip { get; }
    /// <summary>Gets the shared ancestor, or null when the selected tip did not change.</summary>
    public BsvHeaderCheckpoint? CommonAncestor { get; }
    /// <summary>Gets whether this change detached formerly selected headers.</summary>
    public bool IsReorganization { get; }
    /// <summary>Gets detached headers in former-tip-to-ancestor order, excluding the ancestor.</summary>
    public ReadOnlyMemory<BsvHeaderCheckpoint> Detached { get; }
    /// <summary>Gets attached headers in ancestor-child-to-new-tip order.</summary>
    public ReadOnlyMemory<BsvHeaderCheckpoint> Attached { get; }

    private static BsvHeaderCheckpoint[] ExportHeaders(ReadOnlySpan<AdmittedBlockHeader> headers)
    {
        var result = new BsvHeaderCheckpoint[headers.Length];
        for (var index = 0; index < headers.Length; index++)
        {
            result[index] = BsvSelectedHeaderChain.Export(headers[index]);
        }

        return result;
    }
}

/// <summary>A single-consumer, in-memory BSV mainnet selected-header authority over explicitly trusted bootstrap history.</summary>
/// <remarks>
/// Delegates contextual proof-of-work, DAA ancestry, and cumulative-work selection to Core's
/// protocol authority. It neither performs transport nor owns durable recovery, peer selection,
/// or activation. All admitted branches are retained in memory; the caller must bound the lifetime
/// and intake of this authority. Headers alone never prove transaction inclusion or confirmation.
/// </remarks>
public sealed class BsvSelectedHeaderChain
{
    private readonly BsvMainnetHeaderChainOwner _owner;
    private BsvSelectedHeaderChain(BsvMainnetHeaderChainOwner owner) => _owner = owner;

    /// <summary>Gets the currently selected checkpoint from this authority.</summary>
    public BsvHeaderCheckpoint SelectedTip => Export(_owner.BestTip);

    /// <summary>Imports caller-trusted, linked mainnet bootstrap history at or beyond DAA activation.</summary>
    /// <remarks>
    /// At least 147 headers are required. Hashes, claimed proof of work, linkage, consecutive heights,
    /// and relative cumulative work are checked. The initial height/work anchor and historical
    /// contextual difficulty remain trusted assertions; this is not genesis-to-tip consensus validation.
    /// Caller-sized input is copied; no peer-declared size is used for allocation.
    /// </remarks>
    /// <returns>True with an authority on success; false with null for locally inconsistent or insufficient bootstrap.</returns>
    public static bool TryCreateTrustedBootstrap(ReadOnlySpan<BsvHeaderCheckpoint> bootstrap,
        [NotNullWhen(true)] out BsvSelectedHeaderChain? chain)
    {
        var headers = new AdmittedBlockHeader[bootstrap.Length];
        Span<byte> workBytes = stackalloc byte[32];
        for (var index = 0; index < bootstrap.Length; index++)
        {
            var header = bootstrap[index];
            if (header.CumulativeChainWork.Sign <= 0 || header.CumulativeChainWork.GetBitLength() > 256)
            {
                chain = null;
                return false;
            }

            workBytes.Clear();
            _ = header.CumulativeChainWork.TryWriteBytes(workBytes, out _, isUnsigned: true);
            headers[index] = new AdmittedBlockHeader(header.Header, header.Hash, header.Height, UInt256.FromLittleEndian(workBytes));
        }

        var result = BsvMainnetHeaderChainOwner.CreateFromTrustedBootstrap(headers);
        if (result.TryGetOwner(out var owner))
        {
            chain = new BsvSelectedHeaderChain(owner!);
            return true;
        }

        chain = null;
        return false;
    }

    /// <summary>Admits an untrusted peer header against retained authoritative ancestry and reports any selected-chain change.</summary>
    /// <returns>The admission status; change is non-null only for an admitted candidate.</returns>
    public BsvHeaderCandidateStatus Add(in BlockHeader candidate, out BsvHeaderSelectionChange? change)
    {
        var result = _owner.Add(candidate);
        change = result.Status == HeaderChainCandidateStatus.Admitted
            ? new BsvHeaderSelectionChange(result.ProjectionChange) : null;
        return result.Status switch
        {
            HeaderChainCandidateStatus.Admitted => BsvHeaderCandidateStatus.Admitted,
            HeaderChainCandidateStatus.Duplicate => BsvHeaderCandidateStatus.Duplicate,
            HeaderChainCandidateStatus.UnknownParent => BsvHeaderCandidateStatus.UnknownParent,
            HeaderChainCandidateStatus.InsufficientAncestry => BsvHeaderCandidateStatus.InsufficientAncestry,
            HeaderChainCandidateStatus.ConsensusRejected => BsvHeaderCandidateStatus.ConsensusRejected,
            _ => BsvHeaderCandidateStatus.AuthorityInvariantViolation,
        };
    }

    /// <summary>Checks current selected-chain membership in retained authoritative history, not peer assertions.</summary>
    public bool IsOnSelectedChain(Hash256 hash) => _owner.IsOnSelectedChain(hash);

    internal static BsvHeaderCheckpoint Export(in AdmittedBlockHeader header) =>
        new(header.Header, header.Hash, header.Height,
            new BigInteger(header.CumulativeChainWork.Low64) +
            (new BigInteger(header.CumulativeChainWork.ShiftRight(64).Low64) << 64) +
            (new BigInteger(header.CumulativeChainWork.ShiftRight(128).Low64) << 128) +
            (new BigInteger(header.CumulativeChainWork.ShiftRight(192).Low64) << 192));
}
