using System.Buffers;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Messages;
using Staffetta.Core.Protocol.Relay;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Protocol.Sessions;

internal sealed class BsvPeerSessionFrameProcessor :
    IMessageIngressSink,
    IMessageIngressAdmissionPolicy,
    IMessageIngressPayloadHashPolicy,
    IDisposable
{
    internal const ulong MaximumInventoryCount = 50_000;
    internal const ulong MaximumIgnoredPayloadLength = 1024 * 1024;
    internal const ulong MaximumInventoryPayloadLength =
        3 + (MaximumInventoryCount * InventoryVectorCodec.EncodedLength);

    private const uint TransactionInventoryType = 1;
    private const ulong MinimumLegacyTransactionPayloadLength =
        sizeof(int) + 1 + Hash256.Length + sizeof(uint) + 1 + sizeof(uint) +
        1 + sizeof(long) + 1 + sizeof(uint);
    private const int InventoryBatchLength = 8;

    private readonly BsvHandshakeFrameProcessor _handshakeProcessor;
    private readonly BsvPeerRelayCoordinator _relay = new();
    private readonly InventoryVector[] _inventoryBatch = new InventoryVector[InventoryBatchLength];
    private readonly byte[] _rejectPayload = new byte[RejectPayloadCodec.MaximumPayloadLength];
    private readonly IncrementalInventoryPayloadParser _inventoryParser = new();
    private readonly LegacyTransactionParser _transactionParser;

    private FrameRoute _activeRoute;
    private ulong _activePayloadLength;
    private ulong _activePayloadBytes;
    private int _rejectPayloadLength;
    private bool _hasActiveFrame;
    private bool _hasMatchingBroadcastInventory;
    private bool _hasMatchingFetchInventory;
    private bool _frameAborted;
    private bool _frameProcessingFailed;

    internal BsvPeerSessionFrameProcessor(
        int minimumPeerProtocolVersion,
        ILegacyTransactionSink transactionSink)
    {
        _handshakeProcessor = new BsvHandshakeFrameProcessor(
            minimumPeerProtocolVersion,
            trackEgressProvenance: true);
        _transactionParser = new LegacyTransactionParser(
            transactionSink,
            LegacyTransactionHashMode.ExternalValidatedPayload);
    }

    internal BsvHandshakeState HandshakeState => _handshakeProcessor.Handshake.State;

    internal BsvHandshakeTerminalReason HandshakeTerminalReason =>
        _handshakeProcessor.Handshake.TerminalReason;

    internal bool HasPeerVersion => _handshakeProcessor.Handshake.HasPeerVersion;

    internal int PeerProtocolVersion => _handshakeProcessor.Handshake.PeerProtocolVersion;

    internal ulong PeerNonce => _handshakeProcessor.Handshake.PeerNonce;

    internal bool HasPeerVerack => _handshakeProcessor.Handshake.HasPeerVerack;

    internal bool HasPeerProtoconf => _handshakeProcessor.Handshake.HasPeerProtoconf;

    internal uint EffectivePeerMaximumReceivePayloadLength =>
        _handshakeProcessor.Handshake.EffectivePeerMaximumReceivePayloadLength;

    internal BsvTransactionBroadcastState BroadcastState => _relay.BroadcastState;

    internal BsvTransactionBroadcastTerminalReason BroadcastTerminalReason =>
        _relay.BroadcastTerminalReason;

    internal Hash256 TargetTransactionId => _relay.TargetTransactionId;

    internal bool IsAnnounced => _relay.IsAnnounced;

    internal bool WasRequestedByPeer => _relay.WasRequestedByPeer;

    internal bool IsSentToPeer => _relay.IsSentToPeer;

    internal bool WasObservedFromPeer => _relay.WasObservedFromPeer;

    internal bool IsRejected => _relay.IsRejected;

    internal BsvTransactionFetchState FetchState => _relay.FetchState;

    internal BsvTransactionFetchTerminalReason FetchTerminalReason => _relay.FetchTerminalReason;

    internal Hash256 FetchTargetTransactionId => _relay.FetchTargetTransactionId;

    internal int PendingHandshakeOutputCount => _handshakeProcessor.PendingOutputCount;

    internal int PendingHandshakeEgressIntentCount =>
        _handshakeProcessor.PendingEgressIntentCount;

    internal int PendingBroadcastOutputCount => _relay.PendingBroadcastOutputCount;

    internal int PendingFetchOutputCount => _relay.PendingFetchOutputCount;

    internal bool HasPendingOutputs =>
        PendingHandshakeOutputCount != 0 || _relay.HasPendingOutputs;

    internal bool FrameAborted => _frameAborted || _handshakeProcessor.FrameAborted;

    internal bool FrameProcessingFailed =>
        _frameProcessingFailed || _handshakeProcessor.FrameProcessingFailed;

    internal OperationStatus StartHandshake(ulong localNonce) =>
        _handshakeProcessor.Start(localNonce);

    internal OperationStatus StartBroadcast(in Hash256 transactionId) =>
        _relay.StartBroadcast(transactionId);

    internal OperationStatus StartFetch(in Hash256 transactionId) =>
        _relay.StartFetch(transactionId);

    internal bool TryPeekHandshakeEgressIntent(out BsvHandshakeOutput output) =>
        _handshakeProcessor.TryPeekEgressIntent(out output);

    internal bool CanApplyHandshakeEgressCompletion(
        in BsvPeerSessionEgressCompletion completion)
    {
        if (!_handshakeProcessor.TryPeekEgressIntent(out var intent) ||
            completion.RelayWriteCommitKind != BsvPeerSessionRelayWriteCommitKind.None ||
            completion.TransactionId != default ||
            completion.Value != intent.Value)
        {
            return false;
        }

        return (intent.Kind, completion.SendKind) switch
        {
            (BsvHandshakeOutputKind.SendVersion, BsvPeerSessionSendKind.Version) => true,
            (BsvHandshakeOutputKind.SendVerack, BsvPeerSessionSendKind.Verack) => true,
            (BsvHandshakeOutputKind.SendProtoconf, BsvPeerSessionSendKind.Protoconf) => true,
            (BsvHandshakeOutputKind.SendPong, BsvPeerSessionSendKind.Pong) => true,
            (BsvHandshakeOutputKind.SendPing, BsvPeerSessionSendKind.Ping) => true,
            _ => false,
        };
    }

    internal OperationStatus ApplyHandshakeEgressCompletion(
        in BsvPeerSessionEgressCompletion completion)
    {
        if (!CanApplyHandshakeEgressCompletion(completion) ||
            !_handshakeProcessor.TryPeekEgressIntent(out var intent))
        {
            return OperationStatus.InvalidData;
        }

        return _handshakeProcessor.TryConsumeEgressIntent(intent)
            ? OperationStatus.Done
            : OperationStatus.InvalidData;
    }

    internal bool CanPlanBroadcastEgress(in BsvTransactionBroadcastOutput output) =>
        _relay.CanPlanBroadcastEgress(output);

    internal bool CanPlanFetchEgress(in BsvTransactionFetchOutput output) =>
        _relay.CanPlanFetchEgress(output);

    internal bool CanApplyEgressCompletion(in BsvPeerSessionEgressCompletion completion) =>
        _relay.CanApplyEgressCompletion(completion);

    internal OperationStatus ApplyEgressCompletion(in BsvPeerSessionEgressCompletion completion) =>
        _relay.ApplyEgressCompletion(completion);

    internal OperationStatus DrainHandshakeOutputs(
        Span<BsvHandshakeOutput> destination,
        out int outputsWritten) =>
        _handshakeProcessor.DrainOutputs(destination, out outputsWritten);

    internal OperationStatus DrainBroadcastOutputs(
        Span<BsvTransactionBroadcastOutput> destination,
        out int outputsWritten) =>
        _relay.DrainBroadcastOutputs(destination, out outputsWritten);

    internal OperationStatus DrainFetchOutputs(
        Span<BsvTransactionFetchOutput> destination,
        out int outputsWritten) =>
        _relay.DrainFetchOutputs(destination, out outputsWritten);

    internal void BeginConsume()
    {
        _frameAborted = false;
        _frameProcessingFailed = false;
        _handshakeProcessor.BeginConsume();
    }

    internal void BeginCompleteEndOfInput()
    {
        _frameAborted = false;
        _handshakeProcessor.BeginCompleteEndOfInput();
    }

    internal void ApplyWireViolation() => _handshakeProcessor.ApplyWireViolation();

    internal void Terminate(BsvPeerSessionTerminationCause cause)
    {
        _handshakeProcessor.DiscardOutputsAndEgressIntents();
        _relay.Terminate(cause);
    }

    public void Dispose()
    {
        _transactionParser.Dispose();
        _handshakeProcessor.Dispose();
        _relay.Dispose();
        _inventoryBatch.AsSpan().Clear();
        _rejectPayload.AsSpan().Clear();
    }

    bool IMessageIngressAdmissionPolicy.IsAdmitted(in MessageHeader header)
    {
        var route = Classify(header.Command, HandshakeState == BsvHandshakeState.Ready);
        return route switch
        {
            FrameRoute.Inventory or FrameRoute.GetData or FrameRoute.NotFound =>
                HandshakeState == BsvHandshakeState.Ready &&
                header.PayloadLength is >= 1 and <= MaximumInventoryPayloadLength,
            FrameRoute.Transaction =>
                HandshakeState == BsvHandshakeState.Ready &&
                header.PayloadLength >= MinimumLegacyTransactionPayloadLength,
            FrameRoute.RelayReject =>
                header.PayloadLength is >= 3 and <= RejectPayloadCodec.MaximumPayloadLength,
            FrameRoute.EarlyRelay => false,
            FrameRoute.Unknown => header.PayloadLength <= MaximumIgnoredPayloadLength,
            _ => BsvHandshakeFrameProcessor.IsAdmitted(header),
        };
    }

    bool IMessageIngressPayloadHashPolicy.ShouldComputeDoubleSha256(in MessageHeader header) =>
        HandshakeState == BsvHandshakeState.Ready && header.Command.Equals("tx"u8);

    void IMessageIngressSink.OnMessageStarted(in MessageHeader header)
    {
        ResetActiveFrame();
        _hasActiveFrame = true;
        _activePayloadLength = header.PayloadLength;
        _activeRoute = Classify(header.Command, HandshakeState == BsvHandshakeState.Ready);
        switch (_activeRoute)
        {
            case FrameRoute.Handshake:
            case FrameRoute.Unknown:
                _handshakeProcessor.OnMessageStarted(header);
                break;
            case FrameRoute.Inventory:
            case FrameRoute.GetData:
            case FrameRoute.NotFound:
                _inventoryParser.Reset(header.PayloadLength);
                break;
        }
    }

    OperationStatus IMessageIngressSink.OnProvisionalPayload(ReadOnlySpan<byte> payload)
    {
        if (!_hasActiveFrame)
        {
            return OperationStatus.InvalidData;
        }

        return _activeRoute switch
        {
            FrameRoute.Handshake or FrameRoute.Unknown =>
                _handshakeProcessor.OnProvisionalPayload(payload),
            FrameRoute.Inventory or FrameRoute.GetData or FrameRoute.NotFound =>
                ConsumeInventoryPayload(payload),
            FrameRoute.Transaction => ConsumeTransactionPayload(payload),
            FrameRoute.RelayReject => ConsumeRejectPayload(payload),
            _ => OperationStatus.InvalidData,
        };
    }

    void IMessageIngressSink.OnMessageCompleted(in MessageIngressResult result)
    {
        if (!_hasActiveFrame)
        {
            _frameProcessingFailed = true;
            return;
        }

        if (_activeRoute is FrameRoute.Handshake or FrameRoute.Unknown)
        {
            _handshakeProcessor.OnMessageCompleted(result);
            ResetActiveFrame();
            return;
        }

        if (result.Completion == MessageIngressCompletion.FrameAborted)
        {
            _frameAborted = true;
            AbortTransactionIfActive();
            ResetActiveFrame();
            return;
        }

        var status = CompleteValidatedFrame(result);
        if (status != OperationStatus.Done)
        {
            _frameProcessingFailed = true;
            AbortTransactionIfActive();
        }

        ResetActiveFrame();
    }

    private OperationStatus ConsumeInventoryPayload(ReadOnlySpan<byte> payload)
    {
        var offset = 0;
        while (offset < payload.Length)
        {
            var status = _inventoryParser.Consume(
                payload[offset..],
                _inventoryBatch,
                out var bytesConsumed,
                out var vectorsWritten);
            offset += bytesConsumed;

            if (_inventoryParser.VectorCount > MaximumInventoryCount)
            {
                return OperationStatus.InvalidData;
            }

            for (var index = 0; index < vectorsWritten; index++)
            {
                ref readonly var vector = ref _inventoryBatch[index];
                if (vector.Type != TransactionInventoryType)
                {
                    continue;
                }

                _hasMatchingBroadcastInventory |=
                    _relay.MatchesBroadcastTransaction(vector.Hash);
                _hasMatchingFetchInventory |= _relay.MatchesFetchTransaction(vector.Hash);
            }

            _inventoryBatch.AsSpan(0, vectorsWritten).Clear();
            if (status == OperationStatus.InvalidData || bytesConsumed == 0)
            {
                return OperationStatus.InvalidData;
            }

            if (status == OperationStatus.NeedMoreData)
            {
                return offset == payload.Length
                    ? OperationStatus.Done
                    : OperationStatus.InvalidData;
            }

            if (status == OperationStatus.Done)
            {
                return offset == payload.Length
                    ? OperationStatus.Done
                    : OperationStatus.InvalidData;
            }
        }

        return OperationStatus.Done;
    }

    private OperationStatus ConsumeTransactionPayload(ReadOnlySpan<byte> payload)
    {
        var status = _transactionParser.Consume(payload, out var bytesConsumed);
        if (bytesConsumed != payload.Length)
        {
            return OperationStatus.InvalidData;
        }

        _activePayloadBytes += (ulong)bytesConsumed;
        if (_activePayloadBytes > _activePayloadLength)
        {
            return OperationStatus.InvalidData;
        }

        return status switch
        {
            OperationStatus.Done when _activePayloadBytes == _activePayloadLength => OperationStatus.Done,
            OperationStatus.NeedMoreData when _activePayloadBytes < _activePayloadLength =>
                OperationStatus.Done,
            _ => OperationStatus.InvalidData,
        };
    }

    private OperationStatus ConsumeRejectPayload(ReadOnlySpan<byte> payload)
    {
        if (_rejectPayloadLength > _rejectPayload.Length - payload.Length)
        {
            return OperationStatus.InvalidData;
        }

        payload.CopyTo(_rejectPayload.AsSpan(_rejectPayloadLength));
        _rejectPayloadLength += payload.Length;
        return OperationStatus.Done;
    }

    private OperationStatus CompleteValidatedFrame(in MessageIngressResult result)
    {
        switch (_activeRoute)
        {
            case FrameRoute.Inventory:
            case FrameRoute.GetData:
            case FrameRoute.NotFound:
                if (_inventoryParser.Complete() != OperationStatus.Done)
                {
                    return OperationStatus.InvalidData;
                }

                return _activeRoute switch
                {
                    FrameRoute.Inventory => _relay.OnPeerInventory(
                        _hasMatchingBroadcastInventory,
                        _hasMatchingFetchInventory),
                    FrameRoute.GetData => _relay.OnPeerGetData(
                        _hasMatchingBroadcastInventory),
                    _ => _relay.OnPeerNotFound(_hasMatchingFetchInventory),
                };

            case FrameRoute.Transaction:
                if (!_transactionParser.IsReadyToCommit ||
                    _activePayloadBytes != _activePayloadLength ||
                    result.PayloadDoubleSha256 is not Hash256 payloadHash)
                {
                    return OperationStatus.InvalidData;
                }

                var commitStatus = _transactionParser.Commit(
                    payloadHash,
                    _activePayloadLength,
                    out var summary);
                return commitStatus == OperationStatus.Done
                    ? _relay.OnPeerTransaction(summary.TransactionId)
                    : commitStatus;

            case FrameRoute.RelayReject:
                var rejectStatus = RejectPayloadCodec.TryParse(
                    _rejectPayload.AsSpan(0, _rejectPayloadLength),
                    out var reject,
                    out var bytesConsumed);
                if (rejectStatus != OperationStatus.Done ||
                    bytesConsumed != _rejectPayloadLength ||
                    !reject.Command.SequenceEqual("tx"u8) ||
                    !reject.TryGetObjectHash(out var rejectedTransactionId))
                {
                    return rejectStatus == OperationStatus.Done
                        ? OperationStatus.Done
                        : OperationStatus.InvalidData;
                }

                return _relay.OnCorrelatedTransactionReject(rejectedTransactionId);

            default:
                return OperationStatus.Done;
        }
    }

    private void AbortTransactionIfActive()
    {
        if (_activeRoute == FrameRoute.Transaction && !_transactionParser.IsFaulted)
        {
            _transactionParser.Abort();
        }
    }

    private void ResetActiveFrame()
    {
        _rejectPayload.AsSpan(0, _rejectPayloadLength).Clear();
        _inventoryBatch.AsSpan().Clear();
        _activeRoute = FrameRoute.None;
        _activePayloadLength = 0;
        _activePayloadBytes = 0;
        _rejectPayloadLength = 0;
        _hasActiveFrame = false;
        _hasMatchingBroadcastInventory = false;
        _hasMatchingFetchInventory = false;
    }

    private static FrameRoute Classify(in MessageCommand command, bool isReady)
    {
        if (command.Equals("inv"u8))
        {
            return isReady ? FrameRoute.Inventory : FrameRoute.EarlyRelay;
        }

        if (command.Equals("getdata"u8))
        {
            return isReady ? FrameRoute.GetData : FrameRoute.EarlyRelay;
        }

        if (command.Equals("notfound"u8))
        {
            return isReady ? FrameRoute.NotFound : FrameRoute.EarlyRelay;
        }

        if (command.Equals("tx"u8))
        {
            return isReady ? FrameRoute.Transaction : FrameRoute.EarlyRelay;
        }

        if (command.Equals("reject"u8) && isReady)
        {
            return FrameRoute.RelayReject;
        }

        if (command.Equals("version"u8) ||
            command.Equals("verack"u8) ||
            command.Equals("ping"u8) ||
            command.Equals("pong"u8) ||
            command.Equals("protoconf"u8) ||
            command.Equals("reject"u8))
        {
            return FrameRoute.Handshake;
        }

        return FrameRoute.Unknown;
    }

    private enum FrameRoute
    {
        None,
        Unknown,
        Handshake,
        Inventory,
        GetData,
        NotFound,
        Transaction,
        RelayReject,
        EarlyRelay,
    }
}
