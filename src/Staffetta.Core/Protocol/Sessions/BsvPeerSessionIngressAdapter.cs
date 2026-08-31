using System.Buffers;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Messages;
using Staffetta.Core.Protocol.Relay;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Protocol.Sessions;

/// <summary>
/// Composes BSV framing, handshake, transaction relay, and streaming transaction parsing for one
/// peer without performing transport writes.
/// </summary>
/// <remarks>
/// Instances are single-consumer and not thread-safe. Every pending output must be drained before
/// more input is consumed. Draining a send intent never acknowledges a transport write; callers
/// must apply the corresponding write-committed method only after the full write succeeds.
/// Transaction sink callbacks remain provisional until both the transaction structure and its
/// enclosing frame are validated.
/// </remarks>
public sealed class BsvPeerSessionIngressAdapter :
    IMessageIngressSink,
    IMessageIngressAdmissionPolicy,
    IMessageIngressPayloadHashPolicy,
    IDisposable
{
    public const ulong MaximumInventoryCount = 50_000;

    public const ulong MaximumIgnoredPayloadLength = 1024 * 1024;

    public const ulong MaximumInventoryPayloadLength =
        3 + (MaximumInventoryCount * InventoryVectorCodec.EncodedLength);

    private const uint TransactionInventoryType = 1;
    private const ulong MinimumLegacyTransactionPayloadLength =
        sizeof(int) + 1 + Hash256.Length + sizeof(uint) + 1 + sizeof(uint) +
        1 + sizeof(long) + 1 + sizeof(uint);
    private const int InventoryBatchLength = 8;

    private readonly BsvHandshakeFrameProcessor _handshakeProcessor;
    private readonly BsvTransactionBroadcastOutput[] _broadcastOutputs =
        new BsvTransactionBroadcastOutput[BsvTransactionBroadcastStateMachine.MaximumOutputCount];
    private readonly InventoryVector[] _inventoryBatch = new InventoryVector[InventoryBatchLength];
    private readonly byte[] _rejectPayload = new byte[RejectPayloadCodec.MaximumPayloadLength];
    private readonly IncrementalInventoryPayloadParser _inventoryParser = new();
    private readonly LegacyTransactionParser _transactionParser;
    private readonly MessageIngressStateMachine _ingress;
    private readonly BsvTransactionBroadcastStateMachine _broadcast = new();

    private FrameRoute _activeRoute;
    private ulong _activePayloadLength;
    private ulong _activePayloadBytes;
    private int _rejectPayloadLength;
    private int _broadcastOutputCount;
    private bool _hasActiveFrame;
    private bool _hasMatchingInventory;
    private bool _frameAborted;
    private bool _frameProcessingFailed;
    private bool _isOperating;
    private bool _callbackReentryDetected;
    private bool _isIngressUnusable;
    private bool _isCompleted;
    private bool _isDisposed;

    public BsvPeerSessionIngressAdapter(
        ReadOnlySpan<byte> expectedNetworkMagic,
        ulong maximumPayloadLength,
        int minimumPeerProtocolVersion,
        ILegacyTransactionSink transactionSink)
    {
        _handshakeProcessor = new BsvHandshakeFrameProcessor(minimumPeerProtocolVersion);
        _transactionParser = new LegacyTransactionParser(
            new GuardedTransactionSink(
                this,
                transactionSink ?? throw new ArgumentNullException(nameof(transactionSink))),
            LegacyTransactionHashMode.ExternalValidatedPayload);
        _ingress = new MessageIngressStateMachine(
            expectedNetworkMagic,
            maximumPayloadLength,
            this,
            this,
            this);
    }

    public BsvHandshakeState HandshakeState => _handshakeProcessor.Handshake.State;

    public BsvHandshakeTerminalReason HandshakeTerminalReason =>
        _handshakeProcessor.Handshake.TerminalReason;

    public bool HasPeerVersion => _handshakeProcessor.Handshake.HasPeerVersion;

    public int PeerProtocolVersion => _handshakeProcessor.Handshake.PeerProtocolVersion;

    public ulong PeerNonce => _handshakeProcessor.Handshake.PeerNonce;

    public bool HasPeerVerack => _handshakeProcessor.Handshake.HasPeerVerack;

    public bool HasPeerProtoconf => _handshakeProcessor.Handshake.HasPeerProtoconf;

    public uint EffectivePeerMaximumReceivePayloadLength =>
        _handshakeProcessor.Handshake.EffectivePeerMaximumReceivePayloadLength;

    public BsvTransactionBroadcastState BroadcastState => _broadcast.State;

    public BsvTransactionBroadcastTerminalReason BroadcastTerminalReason =>
        _broadcast.TerminalReason;

    public Hash256 TargetTransactionId => _broadcast.TargetTransactionId;

    public bool IsAnnounced => _broadcast.IsAnnounced;

    public bool WasRequestedByPeer => _broadcast.WasRequestedByPeer;

    public bool IsSentToPeer => _broadcast.IsSentToPeer;

    public bool WasObservedFromPeer => _broadcast.WasObservedFromPeer;

    public bool IsRejected => _broadcast.IsRejected;

    public int PendingHandshakeOutputCount => _handshakeProcessor.PendingOutputCount;

    public int PendingBroadcastOutputCount => _broadcastOutputCount;

    public bool HasPendingOutputs =>
        PendingHandshakeOutputCount != 0 || PendingBroadcastOutputCount != 0;

    public OperationStatus StartHandshake(ulong localNonce)
    {
        ThrowIfUnavailable();
        if (_isCompleted || _isIngressUnusable || HasPendingOutputs)
        {
            return HasPendingOutputs
                ? OperationStatus.DestinationTooSmall
                : OperationStatus.InvalidData;
        }

        return _handshakeProcessor.Start(localNonce);
    }

    public OperationStatus StartBroadcast(Hash256 transactionId)
    {
        ThrowIfUnavailable();
        if (_isCompleted ||
            _isIngressUnusable ||
            HandshakeState != BsvHandshakeState.Ready)
        {
            return OperationStatus.InvalidData;
        }

        if (HasPendingOutputs)
        {
            return OperationStatus.DestinationTooSmall;
        }

        var status = _broadcast.Start(transactionId, _broadcastOutputs, out var outputsWritten);
        if (status == OperationStatus.Done)
        {
            _broadcastOutputCount = outputsWritten;
        }

        return status;
    }

    /// <summary>Records that the complete inventory send intent reached the transport.</summary>
    public OperationStatus ApplyInventoryWriteCommitted(Hash256 transactionId) =>
        ApplyBroadcastWriteCommit(BsvTransactionBroadcastInput.InventoryWriteCommitted(transactionId));

    /// <summary>Records that the complete transaction send intent reached the transport.</summary>
    public OperationStatus ApplyTransactionWriteCommitted(Hash256 transactionId) =>
        ApplyBroadcastWriteCommit(BsvTransactionBroadcastInput.TransactionWriteCommitted(transactionId));

    /// <summary>Consumes no more than one complete wire frame.</summary>
    public OperationStatus Consume(ReadOnlySpan<byte> source, out int bytesConsumed)
    {
        ThrowIfUnavailable();
        bytesConsumed = 0;
        if (_isCompleted ||
            _isIngressUnusable ||
            HandshakeState is BsvHandshakeState.Created or BsvHandshakeState.Terminal)
        {
            return OperationStatus.InvalidData;
        }

        if (HasPendingOutputs)
        {
            return OperationStatus.DestinationTooSmall;
        }

        _isOperating = true;
        _frameAborted = false;
        _frameProcessingFailed = false;
        _handshakeProcessor.BeginConsume();
        OperationStatus status;
        try
        {
            status = _ingress.ConsumeSingleFrame(source, out bytesConsumed);
        }
        catch
        {
            _isIngressUnusable = true;
            TerminateBroadcast(BsvTransactionBroadcastInput.ExternalFailure());
            throw;
        }
        finally
        {
            _isOperating = false;
        }

        _frameAborted |= _handshakeProcessor.FrameAborted;
        _frameProcessingFailed |= _handshakeProcessor.FrameProcessingFailed;
        if (status == OperationStatus.InvalidData || _frameAborted || _frameProcessingFailed)
        {
            _isIngressUnusable = true;
            TerminateBroadcast(BsvTransactionBroadcastInput.WireViolation());
            if (!_frameAborted)
            {
                _handshakeProcessor.ApplyWireViolation();
            }

            return OperationStatus.InvalidData;
        }

        return status;
    }

    public OperationStatus DrainHandshakeOutputs(
        Span<BsvHandshakeOutput> destination,
        out int outputsWritten)
    {
        ThrowIfUnavailable();
        return _handshakeProcessor.DrainOutputs(destination, out outputsWritten);
    }

    public OperationStatus DrainBroadcastOutputs(
        Span<BsvTransactionBroadcastOutput> destination,
        out int outputsWritten)
    {
        ThrowIfUnavailable();
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

    public OperationStatus CompleteEndOfInput()
    {
        ThrowIfUnavailable();
        if (_isIngressUnusable)
        {
            return OperationStatus.InvalidData;
        }

        if (_isCompleted)
        {
            return OperationStatus.Done;
        }

        _isOperating = true;
        _frameAborted = false;
        _handshakeProcessor.BeginCompleteEndOfInput();
        OperationStatus status;
        try
        {
            status = _ingress.CompleteEndOfInput();
        }
        catch
        {
            _isIngressUnusable = true;
            TerminateBroadcast(BsvTransactionBroadcastInput.ExternalFailure());
            throw;
        }
        finally
        {
            _isOperating = false;
        }

        _frameAborted |= _handshakeProcessor.FrameAborted;
        if (status == OperationStatus.InvalidData)
        {
            _isIngressUnusable = true;
            TerminateBroadcast(BsvTransactionBroadcastInput.Disconnected());
            return status;
        }

        _isCompleted = true;
        TerminateBroadcast(BsvTransactionBroadcastInput.Disconnected());
        return OperationStatus.Done;
    }

    public void Dispose()
    {
        if (_isDisposed)
        {
            return;
        }

        if (_isOperating)
        {
            _callbackReentryDetected = true;
            _isIngressUnusable = true;
            throw new InvalidOperationException("Peer session cannot be disposed from an ingress callback.");
        }

        TerminateBroadcast(BsvTransactionBroadcastInput.Disconnected());
        _transactionParser.Dispose();
        _handshakeProcessor.Dispose();
        _ingress.Dispose();
        _broadcastOutputs.AsSpan().Clear();
        _inventoryBatch.AsSpan().Clear();
        _rejectPayload.AsSpan().Clear();
        _isDisposed = true;
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

    private OperationStatus ApplyBroadcastWriteCommit(BsvTransactionBroadcastInput input)
    {
        ThrowIfUnavailable();
        if (_isCompleted || _isIngressUnusable || HandshakeState != BsvHandshakeState.Ready)
        {
            return OperationStatus.InvalidData;
        }

        if (HasPendingOutputs)
        {
            return OperationStatus.DestinationTooSmall;
        }

        return ApplyBroadcast(input);
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
                _hasMatchingInventory |=
                    vector.Type == TransactionInventoryType &&
                    BroadcastState != BsvTransactionBroadcastState.Created &&
                    vector.Hash == TargetTransactionId;
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
            OperationStatus.NeedMoreData when _activePayloadBytes < _activePayloadLength => OperationStatus.Done,
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

                if (!_hasMatchingInventory ||
                    BroadcastState == BsvTransactionBroadcastState.Created)
                {
                    return OperationStatus.Done;
                }

                return _activeRoute switch
                {
                    FrameRoute.Inventory => ApplyBroadcast(
                        BsvTransactionBroadcastInput.PeerInventory(TargetTransactionId)),
                    FrameRoute.GetData => ApplyBroadcast(
                        BsvTransactionBroadcastInput.PeerGetData(TargetTransactionId)),
                    _ => OperationStatus.Done,
                };

            case FrameRoute.Transaction:
                if (!_transactionParser.IsReadyToCommit ||
                    _activePayloadBytes != _activePayloadLength ||
                    result.PayloadDoubleSha256 is not Hash256 payloadHash)
                {
                    return OperationStatus.InvalidData;
                }

                return _transactionParser.Commit(
                    payloadHash,
                    _activePayloadLength,
                    out _);

            case FrameRoute.RelayReject:
                var rejectStatus = RejectPayloadCodec.TryParse(
                    _rejectPayload.AsSpan(0, _rejectPayloadLength),
                    out var reject,
                    out var bytesConsumed);
                if (rejectStatus != OperationStatus.Done ||
                    bytesConsumed != _rejectPayloadLength ||
                    !reject.Command.SequenceEqual("tx"u8) ||
                    !reject.TryGetObjectHash(out var rejectedTransactionId) ||
                    BroadcastState == BsvTransactionBroadcastState.Created)
                {
                    return rejectStatus == OperationStatus.Done
                        ? OperationStatus.Done
                        : OperationStatus.InvalidData;
                }

                return ApplyBroadcast(
                    BsvTransactionBroadcastInput.CorrelatedTransactionReject(rejectedTransactionId));

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

    private void TerminateBroadcast(BsvTransactionBroadcastInput input)
    {
        _broadcastOutputs.AsSpan().Clear();
        _broadcastOutputCount = 0;
        Span<BsvHandshakeOutput> discardedHandshakeOutputs =
            stackalloc BsvHandshakeOutput[BsvHandshakeStateMachine.MaximumOutputCount];
        _ = _handshakeProcessor.DrainOutputs(discardedHandshakeOutputs, out _);
        if (BroadcastState is BsvTransactionBroadcastState.Created or
            BsvTransactionBroadcastState.Terminal)
        {
            return;
        }

        _ = _broadcast.Apply(input, _broadcastOutputs, out _);
        _broadcastOutputs.AsSpan().Clear();
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
        _hasMatchingInventory = false;
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (_isOperating)
        {
            _callbackReentryDetected = true;
            _isIngressUnusable = true;
            throw new InvalidOperationException("Peer session cannot be re-entered from an ingress callback.");
        }
    }

    private void ThrowIfCallbackReentered()
    {
        if (_callbackReentryDetected)
        {
            throw new InvalidOperationException(
                "A transaction sink attempted to re-enter the peer session.");
        }
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

    private sealed class GuardedTransactionSink : ILegacyTransactionSink
    {
        private readonly BsvPeerSessionIngressAdapter _owner;
        private readonly ILegacyTransactionSink _inner;

        internal GuardedTransactionSink(
            BsvPeerSessionIngressAdapter owner,
            ILegacyTransactionSink inner)
        {
            _owner = owner;
            _inner = inner;
        }

        public void OnTransactionStarted(int version, ulong inputCount)
        {
            _inner.OnTransactionStarted(version, inputCount);
            _owner.ThrowIfCallbackReentered();
        }

        public void OnInputStarted(
            ulong inputIndex,
            in OutPoint previousOutput,
            ulong scriptLength)
        {
            _inner.OnInputStarted(inputIndex, previousOutput, scriptLength);
            _owner.ThrowIfCallbackReentered();
        }

        public void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script)
        {
            _inner.OnInputScriptChunk(inputIndex, script);
            _owner.ThrowIfCallbackReentered();
        }

        public void OnInputCompleted(ulong inputIndex, uint sequence)
        {
            _inner.OnInputCompleted(inputIndex, sequence);
            _owner.ThrowIfCallbackReentered();
        }

        public void OnOutputsStarted(ulong outputCount)
        {
            _inner.OnOutputsStarted(outputCount);
            _owner.ThrowIfCallbackReentered();
        }

        public void OnOutputStarted(ulong outputIndex, long valueSatoshis, ulong scriptLength)
        {
            _inner.OnOutputStarted(outputIndex, valueSatoshis, scriptLength);
            _owner.ThrowIfCallbackReentered();
        }

        public void OnOutputScriptChunk(ulong outputIndex, ReadOnlySpan<byte> script)
        {
            _inner.OnOutputScriptChunk(outputIndex, script);
            _owner.ThrowIfCallbackReentered();
        }

        public void OnOutputCompleted(ulong outputIndex)
        {
            _inner.OnOutputCompleted(outputIndex);
            _owner.ThrowIfCallbackReentered();
        }

        public void OnTransactionCommitted(in LegacyTransactionSummary summary)
        {
            _inner.OnTransactionCommitted(summary);
            _owner.ThrowIfCallbackReentered();
        }

        public void OnTransactionAborted()
        {
            _inner.OnTransactionAborted();
            _owner.ThrowIfCallbackReentered();
        }
    }
}
