using System.Buffers;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Relay;
using Staffetta.Core.Protocol.Sessions;

namespace Staffetta.Core.Protocol.Transport;

internal enum BsvPeerSessionOutputDispatchKind
{
    Advanced,
    FactPending,
    TransactionRequested,
    InvalidData,
}

internal readonly record struct BsvPeerSessionOutputDispatch(
    BsvPeerSessionOutputDispatchKind Kind,
    BsvTransactionBroadcastOutput TransactionRequest)
{
    internal static BsvPeerSessionOutputDispatch Advanced =>
        new(BsvPeerSessionOutputDispatchKind.Advanced, default);

    internal static BsvPeerSessionOutputDispatch FactPending =>
        new(BsvPeerSessionOutputDispatchKind.FactPending, default);

    internal static BsvPeerSessionOutputDispatch InvalidData =>
        new(BsvPeerSessionOutputDispatchKind.InvalidData, default);

    internal static BsvPeerSessionOutputDispatch RequestTransaction(
        BsvTransactionBroadcastOutput output) =>
        new(BsvPeerSessionOutputDispatchKind.TransactionRequested, output);
}

internal sealed class BsvPeerSessionOutputDispatcher
{
    private readonly BsvPeerSessionIngressAdapter _session;
    private readonly BsvPeerLocalHandshakeConfiguration _localHandshake;
    private readonly IBsvPeerSessionFactSink _factSink;
    private readonly BsvHandshakeOutput[] _handshakeOutputs =
        new BsvHandshakeOutput[BsvHandshakeStateMachine.MaximumOutputCount];
    private readonly BsvTransactionBroadcastOutput[] _broadcastOutputs =
        new BsvTransactionBroadcastOutput[BsvTransactionBroadcastStateMachine.MaximumOutputCount];
    private readonly BsvTransactionFetchOutput[] _fetchOutputs =
        new BsvTransactionFetchOutput[BsvTransactionFetchStateMachine.MaximumOutputCount];

    private int _handshakeOutputIndex;
    private int _handshakeOutputCount;
    private int _broadcastOutputIndex;
    private int _broadcastOutputCount;
    private int _fetchOutputIndex;
    private int _fetchOutputCount;

    internal BsvPeerSessionOutputDispatcher(
        BsvPeerSessionIngressAdapter session,
        BsvPeerLocalHandshakeConfiguration localHandshake,
        IBsvPeerSessionFactSink factSink)
    {
        _session = session ?? throw new ArgumentNullException(nameof(session));
        _localHandshake = localHandshake ?? throw new ArgumentNullException(nameof(localHandshake));
        _factSink = factSink ?? throw new ArgumentNullException(nameof(factSink));
    }

    internal bool HasStagedOutputs =>
        _handshakeOutputIndex != _handshakeOutputCount ||
        _broadcastOutputIndex != _broadcastOutputCount ||
        _fetchOutputIndex != _fetchOutputCount;

    internal bool TryStageOutputs()
    {
        if (HasStagedOutputs)
        {
            return true;
        }

        if (_session.PendingHandshakeOutputCount != 0)
        {
            var status = _session.DrainHandshakeOutputs(_handshakeOutputs, out _handshakeOutputCount);
            _handshakeOutputIndex = 0;
            return status == OperationStatus.Done;
        }

        if (_session.PendingBroadcastOutputCount != 0)
        {
            var status = _session.DrainBroadcastOutputs(_broadcastOutputs, out _broadcastOutputCount);
            _broadcastOutputIndex = 0;
            return status == OperationStatus.Done;
        }

        if (_session.PendingFetchOutputCount != 0)
        {
            var status = _session.DrainFetchOutputs(_fetchOutputs, out _fetchOutputCount);
            _fetchOutputIndex = 0;
            return status == OperationStatus.Done;
        }

        return !_session.HasPendingOutputs;
    }

    internal BsvPeerSessionOutputDispatch DispatchNext()
    {
        if (_handshakeOutputIndex != _handshakeOutputCount)
        {
            return DispatchHandshakeOutput(_handshakeOutputs[_handshakeOutputIndex]);
        }

        if (_broadcastOutputIndex != _broadcastOutputCount)
        {
            return DispatchBroadcastOutput(_broadcastOutputs[_broadcastOutputIndex]);
        }

        if (_fetchOutputIndex != _fetchOutputCount)
        {
            return DispatchFetchOutput(_fetchOutputs[_fetchOutputIndex]);
        }

        return BsvPeerSessionOutputDispatch.InvalidData;
    }

    internal ValueTask DeliverFactAsync(BsvPeerSessionOutputDispatch dispatch)
    {
        if (dispatch.Kind != BsvPeerSessionOutputDispatchKind.FactPending)
        {
            throw new InvalidOperationException("The dispatch does not represent a pending fact.");
        }

        if (_handshakeOutputIndex != _handshakeOutputCount &&
            IsHandshakeFact(_handshakeOutputs[_handshakeOutputIndex].Kind))
        {
            return _factSink.OnHandshakeFactAsync(
                _handshakeOutputs[_handshakeOutputIndex],
                CancellationToken.None);
        }

        if (_broadcastOutputIndex != _broadcastOutputCount &&
            !IsBroadcastSend(_broadcastOutputs[_broadcastOutputIndex].Kind))
        {
            return _factSink.OnBroadcastFactAsync(
                _broadcastOutputs[_broadcastOutputIndex],
                CancellationToken.None);
        }

        if (_fetchOutputIndex != _fetchOutputCount &&
            _fetchOutputs[_fetchOutputIndex].Kind != BsvTransactionFetchOutputKind.SendGetData)
        {
            return _factSink.OnFetchFactAsync(
                _fetchOutputs[_fetchOutputIndex],
                CancellationToken.None);
        }

        throw new InvalidOperationException("The staged output is not a fact.");
    }

    internal bool TryCommit(BsvPeerSessionOutputDispatch dispatch)
    {
        if (dispatch.Kind == BsvPeerSessionOutputDispatchKind.FactPending)
        {
            if (_handshakeOutputIndex != _handshakeOutputCount &&
                IsHandshakeFact(_handshakeOutputs[_handshakeOutputIndex].Kind))
            {
                AdvanceHandshakeOutput();
                return true;
            }

            if (_broadcastOutputIndex != _broadcastOutputCount &&
                !IsBroadcastSend(_broadcastOutputs[_broadcastOutputIndex].Kind))
            {
                AdvanceBroadcastOutput();
                return true;
            }

            if (_fetchOutputIndex != _fetchOutputCount &&
                _fetchOutputs[_fetchOutputIndex].Kind != BsvTransactionFetchOutputKind.SendGetData)
            {
                AdvanceFetchOutput();
                return true;
            }

            return false;
        }

        if (dispatch.Kind == BsvPeerSessionOutputDispatchKind.TransactionRequested &&
            _broadcastOutputIndex != _broadcastOutputCount &&
            _broadcastOutputs[_broadcastOutputIndex] == dispatch.TransactionRequest &&
            dispatch.TransactionRequest.Kind == BsvTransactionBroadcastOutputKind.SendTransaction)
        {
            AdvanceBroadcastOutput();
            return true;
        }

        return false;
    }

    private BsvPeerSessionOutputDispatch DispatchHandshakeOutput(
        BsvHandshakeOutput output)
    {
        if (IsHandshakeFact(output.Kind))
        {
            return BsvPeerSessionOutputDispatch.FactPending;
        }

        OperationStatus status;
        if (output.Kind == BsvHandshakeOutputKind.SendVersion)
        {
            status = _session.PlanVersionEgress(_localHandshake.CreateVersionPayload());
        }
        else if (output.Kind == BsvHandshakeOutputKind.SendProtoconf)
        {
            status = _session.PlanProtoconfEgress(
                _localHandshake.MaximumReceivePayloadLength,
                _localHandshake.StreamPolicies,
                _localHandshake.IncludeStreamPolicies);
        }
        else
        {
            status = _session.PlanNextHandshakeEgress();
        }

        if (status != OperationStatus.Done)
        {
            return BsvPeerSessionOutputDispatch.InvalidData;
        }

        AdvanceHandshakeOutput();
        return BsvPeerSessionOutputDispatch.Advanced;
    }

    private BsvPeerSessionOutputDispatch DispatchBroadcastOutput(
        BsvTransactionBroadcastOutput output)
    {
        if (output.Kind == BsvTransactionBroadcastOutputKind.SendInventory)
        {
            var status = _session.PlanBroadcastEgress(output, out var disposition);
            if (status != OperationStatus.Done || disposition != BsvPeerSessionOutputDisposition.Send)
            {
                return BsvPeerSessionOutputDispatch.InvalidData;
            }

            AdvanceBroadcastOutput();
            return BsvPeerSessionOutputDispatch.Advanced;
        }

        if (output.Kind == BsvTransactionBroadcastOutputKind.SendTransaction)
        {
            return BsvPeerSessionOutputDispatch.RequestTransaction(output);
        }

        return BsvPeerSessionOutputDispatch.FactPending;
    }

    private BsvPeerSessionOutputDispatch DispatchFetchOutput(
        BsvTransactionFetchOutput output)
    {
        if (output.Kind == BsvTransactionFetchOutputKind.SendGetData)
        {
            var status = _session.PlanFetchEgress(output, out var disposition);
            if (status != OperationStatus.Done || disposition != BsvPeerSessionOutputDisposition.Send)
            {
                return BsvPeerSessionOutputDispatch.InvalidData;
            }

            AdvanceFetchOutput();
            return BsvPeerSessionOutputDispatch.Advanced;
        }

        return BsvPeerSessionOutputDispatch.FactPending;
    }

    private void AdvanceHandshakeOutput()
    {
        _handshakeOutputs[_handshakeOutputIndex++] = default;
        if (_handshakeOutputIndex == _handshakeOutputCount)
        {
            _handshakeOutputIndex = 0;
            _handshakeOutputCount = 0;
        }
    }

    private void AdvanceBroadcastOutput()
    {
        _broadcastOutputs[_broadcastOutputIndex++] = default;
        if (_broadcastOutputIndex == _broadcastOutputCount)
        {
            _broadcastOutputIndex = 0;
            _broadcastOutputCount = 0;
        }
    }

    private void AdvanceFetchOutput()
    {
        _fetchOutputs[_fetchOutputIndex++] = default;
        if (_fetchOutputIndex == _fetchOutputCount)
        {
            _fetchOutputIndex = 0;
            _fetchOutputCount = 0;
        }
    }

    private static bool IsHandshakeFact(BsvHandshakeOutputKind kind) => kind is
        BsvHandshakeOutputKind.BecameReady or
        BsvHandshakeOutputKind.PingAcknowledged or
        BsvHandshakeOutputKind.ForwardReject;

    private static bool IsBroadcastSend(BsvTransactionBroadcastOutputKind kind) => kind is
        BsvTransactionBroadcastOutputKind.SendInventory or
        BsvTransactionBroadcastOutputKind.SendTransaction;
}
