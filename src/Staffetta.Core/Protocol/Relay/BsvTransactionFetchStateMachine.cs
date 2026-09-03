using System.Buffers;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Relay;

/// <summary>
/// Drives one transaction fetch from one peer without performing framing or transport.
/// </summary>
/// <remarks>
/// The caller supplies only structurally and frame-validated transaction identifiers. A send
/// output becomes a request fact only after the matching write-committed input is applied.
/// Instances are single-consumer and not thread-safe. Output spans are caller-owned and never retained.
/// </remarks>
public sealed class BsvTransactionFetchStateMachine
{
    /// <summary>The maximum number of outputs produced by a single transition.</summary>
    public const int MaximumOutputCount = 2;

    private Hash256 _targetTransactionId;
    private bool _hasTarget;
    private bool _hasDeferredNotFound;

    /// <summary>Gets the current fetch phase, including terminal Received and NotFound outcomes.</summary>
    public BsvTransactionFetchState State { get; private set; }

    /// <summary>Gets the failure reason, or None for an active fetch or a Received/NotFound outcome.</summary>
    public BsvTransactionFetchTerminalReason TerminalReason { get; private set; }

    /// <summary>Gets the transaction selected by Start, or the default hash before start.</summary>
    public Hash256 TargetTransactionId => _targetTransactionId;

    /// <summary>Selects the target and begins waiting for its inventory; emits no request by itself.</summary>
    /// <param name="transactionId">The target identifier; no transaction bytes are retained.</param>
    /// <returns>Done on the first start; InvalidData if already started. No automatic restart or retry is performed.</returns>
    public OperationStatus Start(Hash256 transactionId)
    {
        if (State != BsvTransactionFetchState.Created)
        {
            return OperationStatus.InvalidData;
        }

        _targetTransactionId = transactionId;
        _hasTarget = true;
        State = BsvTransactionFetchState.AwaitingInventory;
        return OperationStatus.Done;
    }

    /// <summary>Applies one validated peer event, committed-write fact, or caller-reported failure and emits its outputs atomically.</summary>
    /// <param name="input">The event to process; the caller must validate peer data before constructing it.</param>
    /// <param name="destination">Caller-owned output storage; not retained. BsvTransactionFetchStateMachine.MaximumOutputCount slots suffice.</param>
    /// <param name="outputsWritten">The emitted output count, or zero if no output is produced or the call fails.</param>
    /// <returns>Done for an accepted or ignored event; InvalidData for invalid call state or input; DestinationTooSmall without state or destination changes so the same event can be retried.</returns>
    /// <remarks>Received, NotFound, and Terminal states ignore all further inputs and return Done. A matching validated transaction can complete a fetch even before request commitment.</remarks>
    public OperationStatus Apply(
        BsvTransactionFetchInput input,
        Span<BsvTransactionFetchOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (IsTerminal)
        {
            return OperationStatus.Done;
        }

        if (!_hasTarget || input.Kind == BsvTransactionFetchInputKind.None)
        {
            return OperationStatus.InvalidData;
        }

        return input.Kind switch
        {
            BsvTransactionFetchInputKind.PeerInventory =>
                ApplyPeerInventory(input.TransactionId, destination, out outputsWritten),
            BsvTransactionFetchInputKind.GetDataWriteCommitted =>
                ApplyGetDataWriteCommitted(input.TransactionId, destination, out outputsWritten),
            BsvTransactionFetchInputKind.PeerTransaction =>
                ApplyPeerTransaction(input.TransactionId, destination, out outputsWritten),
            BsvTransactionFetchInputKind.PeerNotFound =>
                ApplyPeerNotFound(input.TransactionId, destination, out outputsWritten),
            BsvTransactionFetchInputKind.Disconnected =>
                Terminate(BsvTransactionFetchTerminalReason.Disconnected),
            BsvTransactionFetchInputKind.WireViolation =>
                Terminate(BsvTransactionFetchTerminalReason.WireViolation),
            BsvTransactionFetchInputKind.ExternalFailure =>
                Terminate(BsvTransactionFetchTerminalReason.ExternalFailure),
            _ => OperationStatus.InvalidData,
        };
    }

    private bool IsTerminal =>
        State is BsvTransactionFetchState.Received or
            BsvTransactionFetchState.NotFound or
            BsvTransactionFetchState.Terminal;

    private OperationStatus ApplyPeerInventory(
        Hash256 transactionId,
        Span<BsvTransactionFetchOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (transactionId != _targetTransactionId || State != BsvTransactionFetchState.AwaitingInventory)
        {
            return OperationStatus.Done;
        }

        if (destination.IsEmpty)
        {
            return OperationStatus.DestinationTooSmall;
        }

        State = BsvTransactionFetchState.GetDataWritePending;
        destination[0] = new BsvTransactionFetchOutput(
            BsvTransactionFetchOutputKind.SendGetData,
            transactionId);
        outputsWritten = 1;
        return OperationStatus.Done;
    }

    private OperationStatus ApplyGetDataWriteCommitted(
        Hash256 transactionId,
        Span<BsvTransactionFetchOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (transactionId != _targetTransactionId || State != BsvTransactionFetchState.GetDataWritePending)
        {
            return OperationStatus.InvalidData;
        }

        var requiredOutputCount = _hasDeferredNotFound ? 2 : 1;
        if (destination.Length < requiredOutputCount)
        {
            return OperationStatus.DestinationTooSmall;
        }

        destination[0] = new BsvTransactionFetchOutput(
            BsvTransactionFetchOutputKind.Requested,
            transactionId);
        if (_hasDeferredNotFound)
        {
            _hasDeferredNotFound = false;
            State = BsvTransactionFetchState.NotFound;
            destination[1] = new BsvTransactionFetchOutput(
                BsvTransactionFetchOutputKind.NotFound,
                transactionId);
            outputsWritten = 2;
        }
        else
        {
            State = BsvTransactionFetchState.Requested;
            outputsWritten = 1;
        }

        return OperationStatus.Done;
    }

    private OperationStatus ApplyPeerTransaction(
        Hash256 transactionId,
        Span<BsvTransactionFetchOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (destination.IsEmpty)
        {
            return OperationStatus.DestinationTooSmall;
        }

        var isExpected = transactionId == _targetTransactionId;
        if (isExpected)
        {
            State = BsvTransactionFetchState.Received;
            destination[0] = new BsvTransactionFetchOutput(
                BsvTransactionFetchOutputKind.Received,
                transactionId);
        }
        else
        {
            destination[0] = new BsvTransactionFetchOutput(
                BsvTransactionFetchOutputKind.UnexpectedTransaction,
                transactionId);
        }

        outputsWritten = 1;
        return OperationStatus.Done;
    }

    private OperationStatus ApplyPeerNotFound(
        Hash256 transactionId,
        Span<BsvTransactionFetchOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (transactionId != _targetTransactionId)
        {
            return OperationStatus.Done;
        }

        if (State == BsvTransactionFetchState.GetDataWritePending)
        {
            _hasDeferredNotFound = true;
            return OperationStatus.Done;
        }

        if (State != BsvTransactionFetchState.Requested)
        {
            return OperationStatus.Done;
        }

        if (destination.IsEmpty)
        {
            return OperationStatus.DestinationTooSmall;
        }

        State = BsvTransactionFetchState.NotFound;
        destination[0] = new BsvTransactionFetchOutput(
            BsvTransactionFetchOutputKind.NotFound,
            transactionId);
        outputsWritten = 1;
        return OperationStatus.Done;
    }

    private OperationStatus Terminate(BsvTransactionFetchTerminalReason reason)
    {
        State = BsvTransactionFetchState.Terminal;
        TerminalReason = reason;
        return OperationStatus.Done;
    }
}
