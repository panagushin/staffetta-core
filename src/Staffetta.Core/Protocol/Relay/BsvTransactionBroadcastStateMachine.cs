using System.Buffers;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Relay;

/// <summary>
/// Drives one transaction advertisement to one peer without performing framing or transport.
/// </summary>
/// <remarks>
/// Send outputs are intents. Their corresponding committed inputs are the only events that
/// publish wire-write facts. A peer inventory is an observation, never proof of relay.
/// Instances are single-consumer and not thread-safe. Output spans are caller-owned and never retained.
/// </remarks>
public sealed class BsvTransactionBroadcastStateMachine
{
    /// <summary>The maximum number of outputs produced by a single transition.</summary>
    public const int MaximumOutputCount = 3;

    private Hash256 _targetTransactionId;
    private bool _hasTarget;
    private bool _hasDeferredGetData;
    private bool _hasDeferredReject;

    /// <summary>Gets the current one-peer advertisement phase.</summary>
    public BsvTransactionBroadcastState State { get; private set; }

    /// <summary>Gets the stable terminal reason, or None before termination.</summary>
    public BsvTransactionBroadcastTerminalReason TerminalReason { get; private set; }

    /// <summary>Gets the transaction selected by Start, or the default hash before start.</summary>
    public Hash256 TargetTransactionId => _targetTransactionId;

    /// <summary>Gets whether the target inventory frame write was committed.</summary>
    public bool IsAnnounced { get; private set; }

    /// <summary>Gets whether a matching peer request was accepted after inventory commitment; an earlier racing request is deferred.</summary>
    public bool WasRequestedByPeer { get; private set; }

    /// <summary>Gets whether the complete transaction frame write was committed; peer acceptance is not implied.</summary>
    public bool IsSentToPeer { get; private set; }

    /// <summary>Gets whether the peer advertised the target; this is independent of sending and does not prove onward relay.</summary>
    public bool WasObservedFromPeer { get; private set; }

    /// <summary>Gets whether a validated correlated reject was accepted after transaction write commitment.</summary>
    public bool IsRejected { get; private set; }

    /// <summary>Selects the target once and emits its inventory send intent.</summary>
    /// <param name="transactionId">The target transaction identifier; no transaction bytes are retained.</param>
    /// <param name="destination">Caller-owned output storage; not retained.</param>
    /// <param name="outputsWritten">One on success; otherwise zero.</param>
    /// <returns>Done, InvalidData if already started, or DestinationTooSmall if no output slot is available. Non-success changes neither state nor destination.</returns>
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

    /// <summary>Applies one validated peer event, committed-write fact, or caller-reported failure and emits its outputs atomically.</summary>
    /// <param name="input">The event to process; the caller must validate peer data before constructing it.</param>
    /// <param name="destination">Caller-owned output storage; not retained. BsvTransactionBroadcastStateMachine.MaximumOutputCount slots suffice.</param>
    /// <param name="outputsWritten">The emitted output count, or zero if no output is produced or the call fails.</param>
    /// <returns>Done for an accepted or ignored event; InvalidData for invalid call state or input; DestinationTooSmall without state or destination changes so the same event can be retried.</returns>
    /// <remarks>Terminal state ignores all further inputs and returns Done. Requests racing inventory commitment and rejects racing transaction commitment are deferred until the matching commitment.</remarks>
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
