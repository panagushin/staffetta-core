using System.Buffers;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Relay;

/// <summary>
/// Drives one transaction fetch from one peer without performing framing or transport.
/// </summary>
/// <remarks>
/// The caller supplies only structurally and frame-validated transaction identifiers. A send
/// output becomes a request fact only after the matching write-committed input is applied.
/// </remarks>
public sealed class BsvTransactionFetchStateMachine
{
    public const int MaximumOutputCount = 2;

    private Hash256 _targetTransactionId;
    private bool _hasTarget;
    private bool _hasDeferredNotFound;

    public BsvTransactionFetchState State { get; private set; }

    public BsvTransactionFetchTerminalReason TerminalReason { get; private set; }

    public Hash256 TargetTransactionId => _targetTransactionId;

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
