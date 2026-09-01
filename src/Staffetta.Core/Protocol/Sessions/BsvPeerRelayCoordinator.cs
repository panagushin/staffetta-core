using System.Buffers;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Relay;

namespace Staffetta.Core.Protocol.Sessions;

internal sealed class BsvPeerRelayCoordinator : IDisposable
{
    private readonly BsvTransactionBroadcastOutput[] _broadcastOutputs =
        new BsvTransactionBroadcastOutput[BsvTransactionBroadcastStateMachine.MaximumOutputCount];
    private readonly BsvTransactionFetchOutput[] _fetchOutputs =
        new BsvTransactionFetchOutput[BsvTransactionFetchStateMachine.MaximumOutputCount];
    private readonly BsvTransactionBroadcastStateMachine _broadcast = new();
    private readonly BsvTransactionFetchStateMachine _fetch = new();

    private int _broadcastOutputCount;
    private int _fetchOutputCount;

    internal BsvTransactionBroadcastState BroadcastState => _broadcast.State;

    internal BsvTransactionBroadcastTerminalReason BroadcastTerminalReason =>
        _broadcast.TerminalReason;

    internal Hash256 TargetTransactionId => _broadcast.TargetTransactionId;

    internal bool IsAnnounced => _broadcast.IsAnnounced;

    internal bool WasRequestedByPeer => _broadcast.WasRequestedByPeer;

    internal bool IsSentToPeer => _broadcast.IsSentToPeer;

    internal bool WasObservedFromPeer => _broadcast.WasObservedFromPeer;

    internal bool IsRejected => _broadcast.IsRejected;

    internal BsvTransactionFetchState FetchState => _fetch.State;

    internal BsvTransactionFetchTerminalReason FetchTerminalReason => _fetch.TerminalReason;

    internal Hash256 FetchTargetTransactionId => _fetch.TargetTransactionId;

    internal int PendingBroadcastOutputCount => _broadcastOutputCount;

    internal int PendingFetchOutputCount => _fetchOutputCount;

    internal bool HasPendingOutputs => _broadcastOutputCount != 0 || _fetchOutputCount != 0;

    internal bool MatchesBroadcastTransaction(in Hash256 transactionId) =>
        BroadcastState != BsvTransactionBroadcastState.Created &&
        transactionId == TargetTransactionId;

    internal bool MatchesFetchTransaction(in Hash256 transactionId) =>
        FetchState != BsvTransactionFetchState.Created &&
        transactionId == FetchTargetTransactionId;

    internal OperationStatus StartBroadcast(in Hash256 transactionId)
    {
        var status = _broadcast.Start(transactionId, _broadcastOutputs, out var outputsWritten);
        if (status == OperationStatus.Done)
        {
            _broadcastOutputCount = outputsWritten;
        }

        return status;
    }

    internal OperationStatus StartFetch(in Hash256 transactionId) => _fetch.Start(transactionId);

    internal bool CanPlanBroadcastEgress(in BsvTransactionBroadcastOutput output) =>
        output.TransactionId == TargetTransactionId &&
        output.Kind switch
        {
            BsvTransactionBroadcastOutputKind.SendInventory =>
                BroadcastState == BsvTransactionBroadcastState.InventoryWritePending,
            BsvTransactionBroadcastOutputKind.SendTransaction =>
                BroadcastState == BsvTransactionBroadcastState.TransactionWritePending,
            _ => true,
        };

    internal bool CanPlanFetchEgress(in BsvTransactionFetchOutput output) =>
        output.Kind != BsvTransactionFetchOutputKind.SendGetData ||
        (output.TransactionId == FetchTargetTransactionId &&
            FetchState == BsvTransactionFetchState.GetDataWritePending);

    internal bool CanApplyEgressCompletion(in BsvPeerSessionEgressCompletion completion) =>
        completion.RelayWriteCommitKind switch
        {
            BsvPeerSessionRelayWriteCommitKind.Inventory =>
                completion.SendKind == BsvPeerSessionSendKind.Inventory &&
                BroadcastState == BsvTransactionBroadcastState.InventoryWritePending &&
                completion.TransactionId == TargetTransactionId,
            BsvPeerSessionRelayWriteCommitKind.Transaction =>
                completion.SendKind == BsvPeerSessionSendKind.Transaction &&
                BroadcastState == BsvTransactionBroadcastState.TransactionWritePending &&
                completion.TransactionId == TargetTransactionId,
            BsvPeerSessionRelayWriteCommitKind.GetData =>
                completion.SendKind == BsvPeerSessionSendKind.GetData &&
                FetchState is BsvTransactionFetchState.GetDataWritePending or
                    BsvTransactionFetchState.Received &&
                completion.TransactionId == FetchTargetTransactionId,
            _ => false,
        };

    internal OperationStatus ApplyEgressCompletion(in BsvPeerSessionEgressCompletion completion) =>
        completion.RelayWriteCommitKind switch
        {
            BsvPeerSessionRelayWriteCommitKind.Inventory =>
                ApplyBroadcast(
                    BsvTransactionBroadcastInput.InventoryWriteCommitted(completion.TransactionId)),
            BsvPeerSessionRelayWriteCommitKind.Transaction =>
                ApplyBroadcast(
                    BsvTransactionBroadcastInput.TransactionWriteCommitted(completion.TransactionId)),
            BsvPeerSessionRelayWriteCommitKind.GetData =>
                ApplyFetch(BsvTransactionFetchInput.GetDataWriteCommitted(completion.TransactionId)),
            _ => OperationStatus.InvalidData,
        };

    internal OperationStatus OnPeerInventory(
        bool matchesBroadcast,
        bool matchesFetch)
    {
        if (matchesBroadcast &&
            ApplyBroadcast(BsvTransactionBroadcastInput.PeerInventory(TargetTransactionId)) !=
            OperationStatus.Done)
        {
            return OperationStatus.InvalidData;
        }

        if (matchesFetch &&
            ApplyFetch(BsvTransactionFetchInput.PeerInventory(FetchTargetTransactionId)) !=
            OperationStatus.Done)
        {
            return OperationStatus.InvalidData;
        }

        return OperationStatus.Done;
    }

    internal OperationStatus OnPeerGetData(bool matchesBroadcast) =>
        matchesBroadcast
            ? ApplyBroadcast(BsvTransactionBroadcastInput.PeerGetData(TargetTransactionId))
            : OperationStatus.Done;

    internal OperationStatus OnPeerNotFound(bool matchesFetch) =>
        matchesFetch
            ? ApplyFetch(BsvTransactionFetchInput.PeerNotFound(FetchTargetTransactionId))
            : OperationStatus.Done;

    internal OperationStatus OnPeerTransaction(in Hash256 transactionId) =>
        FetchState == BsvTransactionFetchState.Created
            ? OperationStatus.Done
            : ApplyFetch(BsvTransactionFetchInput.PeerTransaction(transactionId));

    internal OperationStatus OnCorrelatedTransactionReject(in Hash256 transactionId) =>
        BroadcastState == BsvTransactionBroadcastState.Created
            ? OperationStatus.Done
            : ApplyBroadcast(BsvTransactionBroadcastInput.CorrelatedTransactionReject(transactionId));

    internal OperationStatus DrainBroadcastOutputs(
        Span<BsvTransactionBroadcastOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (destination.Length < _broadcastOutputCount)
        {
            return OperationStatus.DestinationTooSmall;
        }

        _broadcastOutputs.AsSpan(0, _broadcastOutputCount).CopyTo(destination);
        outputsWritten = _broadcastOutputCount;
        _broadcastOutputs.AsSpan(0, _broadcastOutputCount).Clear();
        _broadcastOutputCount = 0;
        return OperationStatus.Done;
    }

    internal OperationStatus DrainFetchOutputs(
        Span<BsvTransactionFetchOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (destination.Length < _fetchOutputCount)
        {
            return OperationStatus.DestinationTooSmall;
        }

        _fetchOutputs.AsSpan(0, _fetchOutputCount).CopyTo(destination);
        outputsWritten = _fetchOutputCount;
        _fetchOutputs.AsSpan(0, _fetchOutputCount).Clear();
        _fetchOutputCount = 0;
        return OperationStatus.Done;
    }

    internal void Terminate(BsvPeerSessionTerminationCause cause)
    {
        _broadcastOutputs.AsSpan().Clear();
        _broadcastOutputCount = 0;
        _fetchOutputs.AsSpan().Clear();
        _fetchOutputCount = 0;
        if (BroadcastState is not BsvTransactionBroadcastState.Created and
            not BsvTransactionBroadcastState.Terminal)
        {
            _ = ApplyBroadcast(cause switch
            {
                BsvPeerSessionTerminationCause.WireViolation =>
                    BsvTransactionBroadcastInput.WireViolation(),
                BsvPeerSessionTerminationCause.ExternalFailure =>
                    BsvTransactionBroadcastInput.ExternalFailure(),
                _ => BsvTransactionBroadcastInput.Disconnected(),
            });
            _broadcastOutputs.AsSpan().Clear();
            _broadcastOutputCount = 0;
        }

        if (FetchState is not BsvTransactionFetchState.Created and
            not BsvTransactionFetchState.Received and
            not BsvTransactionFetchState.NotFound and
            not BsvTransactionFetchState.Terminal)
        {
            _ = ApplyFetch(cause switch
            {
                BsvPeerSessionTerminationCause.WireViolation =>
                    BsvTransactionFetchInput.WireViolation(),
                BsvPeerSessionTerminationCause.ExternalFailure =>
                    BsvTransactionFetchInput.ExternalFailure(),
                _ => BsvTransactionFetchInput.Disconnected(),
            });
            _fetchOutputs.AsSpan().Clear();
            _fetchOutputCount = 0;
        }
    }

    public void Dispose()
    {
        _broadcastOutputs.AsSpan().Clear();
        _broadcastOutputCount = 0;
        _fetchOutputs.AsSpan().Clear();
        _fetchOutputCount = 0;
    }

    private OperationStatus ApplyBroadcast(BsvTransactionBroadcastInput input)
    {
        var status = _broadcast.Apply(input, _broadcastOutputs, out var outputsWritten);
        if (status == OperationStatus.Done)
        {
            _broadcastOutputCount = outputsWritten;
        }

        return status;
    }

    private OperationStatus ApplyFetch(BsvTransactionFetchInput input)
    {
        var status = _fetch.Apply(input, _fetchOutputs, out var outputsWritten);
        if (status == OperationStatus.Done)
        {
            _fetchOutputCount = outputsWritten;
        }

        return status;
    }
}

internal enum BsvPeerSessionTerminationCause
{
    Disconnected,
    WireViolation,
    ExternalFailure,
}
