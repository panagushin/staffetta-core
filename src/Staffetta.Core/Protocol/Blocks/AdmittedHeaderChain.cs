using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

internal enum BestChainProjectionChangeKind
{
    None,
    Extended,
    Reorganized,
}

internal readonly struct BestChainProjectionChange
{
    private readonly AdmittedBlockHeader[]? _detached;
    private readonly AdmittedBlockHeader[]? _attached;

    private BestChainProjectionChange(
        BestChainProjectionChangeKind kind,
        AdmittedBlockHeader previousTip,
        AdmittedBlockHeader currentTip,
        AdmittedBlockHeader? commonAncestor,
        AdmittedBlockHeader[] detached,
        AdmittedBlockHeader[] attached)
    {
        Kind = kind;
        PreviousTip = previousTip;
        CurrentTip = currentTip;
        CommonAncestor = commonAncestor;
        _detached = detached;
        _attached = attached;
    }

    internal BestChainProjectionChangeKind Kind { get; }

    internal AdmittedBlockHeader PreviousTip { get; }

    internal AdmittedBlockHeader CurrentTip { get; }

    internal AdmittedBlockHeader? CommonAncestor { get; }

    // Detached is ordered from the former tip back toward, but excluding, the common ancestor.
    internal ReadOnlyMemory<AdmittedBlockHeader> Detached =>
        _detached ?? ReadOnlyMemory<AdmittedBlockHeader>.Empty;

    // Attached is ordered forward from the child of the common ancestor to the new tip.
    internal ReadOnlyMemory<AdmittedBlockHeader> Attached =>
        _attached ?? ReadOnlyMemory<AdmittedBlockHeader>.Empty;

    internal static BestChainProjectionChange NoChange(AdmittedBlockHeader tip) =>
        new(
            BestChainProjectionChangeKind.None,
            tip,
            tip,
            commonAncestor: null,
            [],
            []);

    internal static BestChainProjectionChange Changed(
        AdmittedBlockHeader previousTip,
        AdmittedBlockHeader currentTip,
        AdmittedBlockHeader commonAncestor,
        AdmittedBlockHeader[] detached,
        AdmittedBlockHeader[] attached) =>
        new(
            detached.Length == 0
                ? BestChainProjectionChangeKind.Extended
                : BestChainProjectionChangeKind.Reorganized,
            previousTip,
            currentTip,
            commonAncestor,
            detached,
            attached);
}

internal enum AdmittedHeaderCommitStatus
{
    Committed,
    Duplicate,
    UnknownParent,
    InvalidHeight,
    InvalidCumulativeChainWork,
}

internal readonly record struct AdmittedHeaderCommitResult(
    AdmittedHeaderCommitStatus Status,
    BestChainProjectionChange ProjectionChange);

// This graph accepts admitted evidence only. Peer headers enter through BsvMainnetHeaderChainOwner.
internal sealed class AdmittedHeaderChain
{
    private readonly Dictionary<Hash256, Node> _nodes;
    private Node _bestTip;

    private AdmittedHeaderChain(ReadOnlySpan<AdmittedBlockHeader> trustedBootstrap)
    {
        _nodes = new Dictionary<Hash256, Node>(trustedBootstrap.Length);
        Node? parent = null;
        foreach (AdmittedBlockHeader header in trustedBootstrap)
        {
            var node = new Node(header, parent, isOnCurrentBestChain: true);
            _nodes.Add(header.Hash, node);
            parent = node;
        }

        _bestTip = parent ?? throw new ArgumentException(
            "The admitted bootstrap cannot be empty.",
            nameof(trustedBootstrap));
    }

    internal AdmittedBlockHeader BestTip => _bestTip.Header;

    // The caller must validate the trusted bootstrap before crossing this boundary.
    internal static AdmittedHeaderChain CreateFromValidatedBootstrap(
        ReadOnlySpan<AdmittedBlockHeader> trustedBootstrap) =>
        new(trustedBootstrap);

    internal bool Contains(Hash256 hash) => _nodes.ContainsKey(hash);

    internal bool IsOnCurrentBestChain(Hash256 hash) =>
        _nodes.TryGetValue(hash, out Node? node) && node.IsOnCurrentBestChain;

    internal bool TryGet(Hash256 hash, out AdmittedBlockHeader header)
    {
        if (_nodes.TryGetValue(hash, out Node? node))
        {
            header = node.Header;
            return true;
        }

        header = default;
        return false;
    }

    internal bool TryBuildDifficultyContext(
        Hash256 parentHash,
        Span<BlockDifficultyContext> destination)
    {
        if (destination.Length != BsvMainnetDifficultyAdjustment.RequiredContextLength ||
            !_nodes.TryGetValue(parentHash, out Node? node))
        {
            return false;
        }

        for (var index = destination.Length - 1; index >= 0; index--)
        {
            if (node is null)
            {
                destination.Clear();
                return false;
            }

            destination[index] = new BlockDifficultyContext(
                node.Header.Height,
                node.Header.Header.Timestamp,
                node.Header.CumulativeChainWork);
            node = node.Parent;
        }

        return true;
    }

    internal AdmittedHeaderCommitResult Commit(AdmittedBlockHeader admitted)
    {
        if (_nodes.ContainsKey(admitted.Hash))
        {
            return new AdmittedHeaderCommitResult(
                AdmittedHeaderCommitStatus.Duplicate,
                BestChainProjectionChange.NoChange(_bestTip.Header));
        }

        if (!_nodes.TryGetValue(admitted.Header.PreviousBlockHash, out Node? parent))
        {
            return new AdmittedHeaderCommitResult(
                AdmittedHeaderCommitStatus.UnknownParent,
                BestChainProjectionChange.NoChange(_bestTip.Header));
        }

        if (parent.Header.Height == int.MaxValue || admitted.Height != parent.Header.Height + 1)
        {
            return new AdmittedHeaderCommitResult(
                AdmittedHeaderCommitStatus.InvalidHeight,
                BestChainProjectionChange.NoChange(_bestTip.Header));
        }

        UInt256 expectedChainWork = parent.Header.CumulativeChainWork.Add(
            BlockProofOfWork.GetBlockWork(admitted.Header.Bits));
        if (expectedChainWork <= parent.Header.CumulativeChainWork ||
            admitted.CumulativeChainWork != expectedChainWork)
        {
            return new AdmittedHeaderCommitResult(
                AdmittedHeaderCommitStatus.InvalidCumulativeChainWork,
                BestChainProjectionChange.NoChange(_bestTip.Header));
        }

        var candidate = new Node(admitted, parent, isOnCurrentBestChain: false);
        BestChainProjectionChange projectionChange = admitted.CumulativeChainWork >
            _bestTip.Header.CumulativeChainWork
            ? RecomputeProjection(_bestTip, candidate)
            : BestChainProjectionChange.NoChange(_bestTip.Header);

        _nodes.Add(admitted.Hash, candidate);
        if (projectionChange.Kind != BestChainProjectionChangeKind.None)
        {
            ApplyProjectionMembership(_bestTip, candidate, projectionChange.CommonAncestor);
            _bestTip = candidate;
        }

        return new AdmittedHeaderCommitResult(
            AdmittedHeaderCommitStatus.Committed,
            projectionChange);
    }

    private static void ApplyProjectionMembership(
        Node previousTip,
        Node currentTip,
        AdmittedBlockHeader? commonAncestorHeader)
    {
        if (commonAncestorHeader is not AdmittedBlockHeader commonAncestor)
        {
            throw BrokenAncestry();
        }

        Node cursor = previousTip;
        while (cursor.Header.Hash != commonAncestor.Hash)
        {
            cursor.IsOnCurrentBestChain = false;
            cursor = cursor.Parent ?? throw BrokenAncestry();
        }

        cursor = currentTip;
        while (cursor.Header.Hash != commonAncestor.Hash)
        {
            cursor.IsOnCurrentBestChain = true;
            cursor = cursor.Parent ?? throw BrokenAncestry();
        }
    }

    private static BestChainProjectionChange RecomputeProjection(Node previousTip, Node currentTip)
    {
        Node previousCursor = previousTip;
        Node currentCursor = currentTip;
        while (previousCursor.Header.Height > currentCursor.Header.Height)
        {
            previousCursor = previousCursor.Parent ?? throw BrokenAncestry();
        }

        while (currentCursor.Header.Height > previousCursor.Header.Height)
        {
            currentCursor = currentCursor.Parent ?? throw BrokenAncestry();
        }

        while (previousCursor.Header.Hash != currentCursor.Header.Hash)
        {
            previousCursor = previousCursor.Parent ?? throw BrokenAncestry();
            currentCursor = currentCursor.Parent ?? throw BrokenAncestry();
        }

        Node commonAncestor = previousCursor;
        var detached = new AdmittedBlockHeader[previousTip.Header.Height - commonAncestor.Header.Height];
        previousCursor = previousTip;
        for (var index = 0; index < detached.Length; index++)
        {
            detached[index] = previousCursor.Header;
            previousCursor = previousCursor.Parent ?? throw BrokenAncestry();
        }

        var attached = new AdmittedBlockHeader[currentTip.Header.Height - commonAncestor.Header.Height];
        currentCursor = currentTip;
        for (var index = attached.Length - 1; index >= 0; index--)
        {
            attached[index] = currentCursor.Header;
            currentCursor = currentCursor.Parent ?? throw BrokenAncestry();
        }

        return BestChainProjectionChange.Changed(
            previousTip.Header,
            currentTip.Header,
            commonAncestor.Header,
            detached,
            attached);
    }

    private static InvalidOperationException BrokenAncestry() =>
        new("The admitted header graph contains disconnected ancestry.");

    private sealed class Node
    {
        internal Node(
            AdmittedBlockHeader header,
            Node? parent,
            bool isOnCurrentBestChain)
        {
            Header = header;
            Parent = parent;
            IsOnCurrentBestChain = isOnCurrentBestChain;
        }

        internal AdmittedBlockHeader Header { get; }

        internal Node? Parent { get; }

        internal bool IsOnCurrentBestChain { get; set; }
    }
}
