using System.Buffers;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Relay;

/// <summary>
/// Drives one transaction advertisement to one peer without performing framing or transport.
/// </summary>
/// <remarks>
/// Send outputs are intents. Their corresponding committed inputs are the only events that
/// publish wire-write facts. A peer inventory is an observation, never proof of relay.
/// </remarks>
public sealed class BsvTransactionBroadcastStateMachine
{
    public const int MaximumOutputCount = 3;

    private Hash256 _targetTransactionId;
    private bool _hasTarget;
    private bool _hasDeferredGetData;
    private bool _hasDeferredReject;

    public BsvTransactionBroadcastState State { get; private set; }

    public BsvTransactionBroadcastTerminalReason TerminalReason { get; private set; }

    public Hash256 TargetTransactionId => _targetTransactionId;

    public bool IsAnnounced { get; private set; }

    public bool WasRequestedByPeer { get; private set; }

    public bool IsSentToPeer { get; private set; }

    public bool WasObservedFromPeer { get; private set; }

    public bool IsRejected { get; private set; }

    public OperationStatus Start(
        Hash256 transactionId,
        Span<BsvTransactionBroadcastOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (State != BsvTransactionBroadcastState.Created)
        {
            return OperationStatus.InvalidData;
        }

        if (destination.IsEmpty)
        {
            return OperationStatus.DestinationTooSmall;
        }

        _targetTransactionId = transactionId;
        _hasTarget = true;
        State = BsvTransactionBroadcastState.InventoryWritePending;
        destination[0] = new BsvTransactionBroadcastOutput(
            BsvTransactionBroadcastOutputKind.SendInventory,
            transactionId);
        outputsWritten = 1;
        return OperationStatus.Done;
    }

    public OperationStatus Apply(
        BsvTransactionBroadcastInput input,
        Span<BsvTransactionBroadcastOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (State == BsvTransactionBroadcastState.Terminal)
        {
            return OperationStatus.Done;
        }

        if (!_hasTarget || input.Kind == BsvTransactionBroadcastInputKind.None)
        {
            return OperationStatus.InvalidData;
        }

        return input.Kind switch
        {
            BsvTransactionBroadcastInputKind.InventoryWriteCommitted =>
                ApplyInventoryWriteCommitted(input.TransactionId, destination, out outputsWritten),
            BsvTransactionBroadcastInputKind.PeerGetData =>
                ApplyPeerGetData(input.TransactionId, destination, out outputsWritten),
            BsvTransactionBroadcastInputKind.TransactionWriteCommitted =>
                ApplyTransactionWriteCommitted(input.TransactionId, destination, out outputsWritten),
            BsvTransactionBroadcastInputKind.PeerInventory =>
                ApplyPeerInventory(input.TransactionId, destination, out outputsWritten),
            BsvTransactionBroadcastInputKind.CorrelatedTransactionReject =>
                ApplyPeerReject(input.TransactionId, destination, out outputsWritten),
            BsvTransactionBroadcastInputKind.Disconnected =>
                Terminate(BsvTransactionBroadcastTerminalReason.Disconnected),
            BsvTransactionBroadcastInputKind.WireViolation =>
                Terminate(BsvTransactionBroadcastTerminalReason.WireViolation),
            BsvTransactionBroadcastInputKind.ExternalFailure =>
                Terminate(BsvTransactionBroadcastTerminalReason.ExternalFailure),
            _ => OperationStatus.InvalidData,
        };
    }

    private OperationStatus ApplyInventoryWriteCommitted(
        Hash256 transactionId,
        Span<BsvTransactionBroadcastOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (transactionId != _targetTransactionId || State != BsvTransactionBroadcastState.InventoryWritePending)
        {
            return OperationStatus.InvalidData;
        }

        var requiredOutputCount = _hasDeferredGetData ? 3 : 1;
        if (destination.Length < requiredOutputCount)
        {
            return OperationStatus.DestinationTooSmall;
        }

        IsAnnounced = true;
        destination[0] = new BsvTransactionBroadcastOutput(
            BsvTransactionBroadcastOutputKind.Announced,
            transactionId);
        if (_hasDeferredGetData)
        {
            _hasDeferredGetData = false;
            WasRequestedByPeer = true;
            State = BsvTransactionBroadcastState.TransactionWritePending;
            destination[1] = new BsvTransactionBroadcastOutput(
                BsvTransactionBroadcastOutputKind.RequestedByPeer,
                transactionId);
            destination[2] = new BsvTransactionBroadcastOutput(
                BsvTransactionBroadcastOutputKind.SendTransaction,
                transactionId);
            outputsWritten = 3;
        }
        else
        {
            State = BsvTransactionBroadcastState.Announced;
            outputsWritten = 1;
        }

        return OperationStatus.Done;
    }

    private OperationStatus ApplyPeerGetData(
        Hash256 transactionId,
        Span<BsvTransactionBroadcastOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (transactionId != _targetTransactionId)
        {
            return OperationStatus.Done;
        }

        if (State == BsvTransactionBroadcastState.InventoryWritePending)
        {
            _hasDeferredGetData = true;
            return OperationStatus.Done;
        }

        if (State != BsvTransactionBroadcastState.Announced)
        {
            return OperationStatus.Done;
        }

        if (destination.Length < 2)
        {
            return OperationStatus.DestinationTooSmall;
        }

        WasRequestedByPeer = true;
        State = BsvTransactionBroadcastState.TransactionWritePending;
        destination[0] = new BsvTransactionBroadcastOutput(
            BsvTransactionBroadcastOutputKind.RequestedByPeer,
            transactionId);
        destination[1] = new BsvTransactionBroadcastOutput(
            BsvTransactionBroadcastOutputKind.SendTransaction,
            transactionId);
        outputsWritten = 2;
        return OperationStatus.Done;
    }

    private OperationStatus ApplyTransactionWriteCommitted(
        Hash256 transactionId,
        Span<BsvTransactionBroadcastOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (transactionId != _targetTransactionId ||
            State != BsvTransactionBroadcastState.TransactionWritePending)
        {
            return OperationStatus.InvalidData;
        }

        var requiredOutputCount = _hasDeferredReject ? 2 : 1;
        if (destination.Length < requiredOutputCount)
        {
            return OperationStatus.DestinationTooSmall;
        }

        IsSentToPeer = true;
        destination[0] = new BsvTransactionBroadcastOutput(
            BsvTransactionBroadcastOutputKind.SentToPeer,
            transactionId);
        if (_hasDeferredReject)
        {
            _hasDeferredReject = false;
            IsRejected = true;
            State = BsvTransactionBroadcastState.Terminal;
            TerminalReason = BsvTransactionBroadcastTerminalReason.Rejected;
            destination[1] = new BsvTransactionBroadcastOutput(
                BsvTransactionBroadcastOutputKind.Rejected,
                transactionId);
            outputsWritten = 2;
        }
        else
        {
            State = BsvTransactionBroadcastState.SentToPeer;
            outputsWritten = 1;
        }

        return OperationStatus.Done;
    }

    private OperationStatus ApplyPeerInventory(
        Hash256 transactionId,
        Span<BsvTransactionBroadcastOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (transactionId != _targetTransactionId || WasObservedFromPeer)
        {
            return OperationStatus.Done;
        }

        if (destination.IsEmpty)
        {
            return OperationStatus.DestinationTooSmall;
        }

        WasObservedFromPeer = true;
        destination[0] = new BsvTransactionBroadcastOutput(
            BsvTransactionBroadcastOutputKind.ObservedFromPeer,
            transactionId);
        outputsWritten = 1;
        return OperationStatus.Done;
    }

    private OperationStatus ApplyPeerReject(
        Hash256 transactionId,
        Span<BsvTransactionBroadcastOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (transactionId != _targetTransactionId)
        {
            return OperationStatus.Done;
        }

        if (State == BsvTransactionBroadcastState.TransactionWritePending)
        {
            _hasDeferredReject = true;
            return OperationStatus.Done;
        }

        if (State != BsvTransactionBroadcastState.SentToPeer)
        {
            return OperationStatus.Done;
        }

        if (destination.IsEmpty)
        {
            return OperationStatus.DestinationTooSmall;
        }

        IsRejected = true;
        State = BsvTransactionBroadcastState.Terminal;
        TerminalReason = BsvTransactionBroadcastTerminalReason.Rejected;
        destination[0] = new BsvTransactionBroadcastOutput(
            BsvTransactionBroadcastOutputKind.Rejected,
            transactionId);
        outputsWritten = 1;
        return OperationStatus.Done;
    }

    private OperationStatus Terminate(BsvTransactionBroadcastTerminalReason reason)
    {
        State = BsvTransactionBroadcastState.Terminal;
        TerminalReason = reason;
        return OperationStatus.Done;
    }
}
