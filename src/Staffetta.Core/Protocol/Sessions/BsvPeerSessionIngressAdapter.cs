using System.Buffers;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
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
    public const ulong MaximumInventoryCount = BsvPeerSessionFrameProcessor.MaximumInventoryCount;

    public const ulong MaximumIgnoredPayloadLength =
        BsvPeerSessionFrameProcessor.MaximumIgnoredPayloadLength;

    public const ulong MaximumInventoryPayloadLength =
        BsvPeerSessionFrameProcessor.MaximumInventoryPayloadLength;

    private readonly BsvPeerSessionFrameProcessor _processor;
    private readonly MessageIngressStateMachine _ingress;

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
        _processor = new BsvPeerSessionFrameProcessor(
            minimumPeerProtocolVersion,
            new GuardedTransactionSink(
                this,
                transactionSink ?? throw new ArgumentNullException(nameof(transactionSink))));
        _ingress = new MessageIngressStateMachine(
            expectedNetworkMagic,
            maximumPayloadLength,
            _processor,
            _processor,
            _processor);
    }

    public BsvHandshakeState HandshakeState => _processor.HandshakeState;

    public BsvHandshakeTerminalReason HandshakeTerminalReason =>
        _processor.HandshakeTerminalReason;

    public bool HasPeerVersion => _processor.HasPeerVersion;

    public int PeerProtocolVersion => _processor.PeerProtocolVersion;

    public ulong PeerNonce => _processor.PeerNonce;

    public bool HasPeerVerack => _processor.HasPeerVerack;

    public bool HasPeerProtoconf => _processor.HasPeerProtoconf;

    public uint EffectivePeerMaximumReceivePayloadLength =>
        _processor.EffectivePeerMaximumReceivePayloadLength;

    public BsvTransactionBroadcastState BroadcastState => _processor.BroadcastState;

    public BsvTransactionBroadcastTerminalReason BroadcastTerminalReason =>
        _processor.BroadcastTerminalReason;

    public Hash256 TargetTransactionId => _processor.TargetTransactionId;

    public bool IsAnnounced => _processor.IsAnnounced;

    public bool WasRequestedByPeer => _processor.WasRequestedByPeer;

    public bool IsSentToPeer => _processor.IsSentToPeer;

    public bool WasObservedFromPeer => _processor.WasObservedFromPeer;

    public bool IsRejected => _processor.IsRejected;

    public BsvTransactionFetchState FetchState => _processor.FetchState;

    public BsvTransactionFetchTerminalReason FetchTerminalReason => _processor.FetchTerminalReason;

    public Hash256 FetchTargetTransactionId => _processor.FetchTargetTransactionId;

    public int PendingHandshakeOutputCount => _processor.PendingHandshakeOutputCount;

    public int PendingBroadcastOutputCount => _processor.PendingBroadcastOutputCount;

    public int PendingFetchOutputCount => _processor.PendingFetchOutputCount;

    public bool HasPendingOutputs => _processor.HasPendingOutputs;

    public OperationStatus StartHandshake(ulong localNonce)
    {
        ThrowIfUnavailable();
        if (_isCompleted || _isIngressUnusable || HasPendingOutputs)
        {
            return HasPendingOutputs
                ? OperationStatus.DestinationTooSmall
                : OperationStatus.InvalidData;
        }

        return _processor.StartHandshake(localNonce);
    }

    public OperationStatus StartBroadcast(Hash256 transactionId)
    {
        ThrowIfUnavailable();
        if (!CanApplyReadyTransition())
        {
            return OperationStatus.InvalidData;
        }

        if (HasPendingOutputs)
        {
            return OperationStatus.DestinationTooSmall;
        }

        return _processor.StartBroadcast(transactionId);
    }

    public OperationStatus StartFetch(Hash256 transactionId)
    {
        ThrowIfUnavailable();
        if (!CanApplyReadyTransition())
        {
            return OperationStatus.InvalidData;
        }

        if (HasPendingOutputs)
        {
            return OperationStatus.DestinationTooSmall;
        }

        return _processor.StartFetch(transactionId);
    }

    /// <summary>Records that the complete inventory send intent reached the transport.</summary>
    public OperationStatus ApplyInventoryWriteCommitted(Hash256 transactionId)
    {
        ThrowIfUnavailable();
        if (!CanApplyReadyTransition())
        {
            return OperationStatus.InvalidData;
        }

        if (HasPendingOutputs)
        {
            return OperationStatus.DestinationTooSmall;
        }

        return _processor.ApplyInventoryWriteCommitted(transactionId);
    }

    /// <summary>Records that the complete transaction send intent reached the transport.</summary>
    public OperationStatus ApplyTransactionWriteCommitted(Hash256 transactionId)
    {
        ThrowIfUnavailable();
        if (!CanApplyReadyTransition())
        {
            return OperationStatus.InvalidData;
        }

        if (HasPendingOutputs)
        {
            return OperationStatus.DestinationTooSmall;
        }

        return _processor.ApplyTransactionWriteCommitted(transactionId);
    }

    /// <summary>Records that the complete getdata send intent reached the transport.</summary>
    public OperationStatus ApplyGetDataWriteCommitted(Hash256 transactionId)
    {
        ThrowIfUnavailable();
        if (!CanApplyReadyTransition())
        {
            return OperationStatus.InvalidData;
        }

        if (HasPendingOutputs)
        {
            return OperationStatus.DestinationTooSmall;
        }

        return _processor.ApplyGetDataWriteCommitted(transactionId);
    }

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
        _processor.BeginConsume();
        OperationStatus status;
        try
        {
            status = _ingress.ConsumeSingleFrame(source, out bytesConsumed);
        }
        catch
        {
            _isIngressUnusable = true;
            _processor.Terminate(BsvPeerSessionTerminationCause.ExternalFailure);
            throw;
        }
        finally
        {
            _isOperating = false;
        }

        if (status == OperationStatus.InvalidData ||
            _processor.FrameAborted ||
            _processor.FrameProcessingFailed)
        {
            _isIngressUnusable = true;
            _processor.Terminate(BsvPeerSessionTerminationCause.WireViolation);
            if (!_processor.FrameAborted)
            {
                _processor.ApplyWireViolation();
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
        return _processor.DrainHandshakeOutputs(destination, out outputsWritten);
    }

    public OperationStatus DrainBroadcastOutputs(
        Span<BsvTransactionBroadcastOutput> destination,
        out int outputsWritten)
    {
        ThrowIfUnavailable();
        return _processor.DrainBroadcastOutputs(destination, out outputsWritten);
    }

    public OperationStatus DrainFetchOutputs(
        Span<BsvTransactionFetchOutput> destination,
        out int outputsWritten)
    {
        ThrowIfUnavailable();
        return _processor.DrainFetchOutputs(destination, out outputsWritten);
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
        _processor.BeginCompleteEndOfInput();
        OperationStatus status;
        try
        {
            status = _ingress.CompleteEndOfInput();
        }
        catch
        {
            _isIngressUnusable = true;
            _processor.Terminate(BsvPeerSessionTerminationCause.ExternalFailure);
            throw;
        }
        finally
        {
            _isOperating = false;
        }

        if (status == OperationStatus.InvalidData)
        {
            _isIngressUnusable = true;
            _processor.Terminate(BsvPeerSessionTerminationCause.Disconnected);
            return status;
        }

        _isCompleted = true;
        _processor.Terminate(BsvPeerSessionTerminationCause.Disconnected);
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

        _processor.Terminate(BsvPeerSessionTerminationCause.Disconnected);
        _processor.Dispose();
        _ingress.Dispose();
        _isDisposed = true;
    }

    bool IMessageIngressAdmissionPolicy.IsAdmitted(in MessageHeader header) =>
        ((IMessageIngressAdmissionPolicy)_processor).IsAdmitted(header);

    bool IMessageIngressPayloadHashPolicy.ShouldComputeDoubleSha256(in MessageHeader header) =>
        ((IMessageIngressPayloadHashPolicy)_processor).ShouldComputeDoubleSha256(header);

    void IMessageIngressSink.OnMessageStarted(in MessageHeader header) =>
        ((IMessageIngressSink)_processor).OnMessageStarted(header);

    OperationStatus IMessageIngressSink.OnProvisionalPayload(ReadOnlySpan<byte> payload) =>
        ((IMessageIngressSink)_processor).OnProvisionalPayload(payload);

    void IMessageIngressSink.OnMessageCompleted(in MessageIngressResult result) =>
        ((IMessageIngressSink)_processor).OnMessageCompleted(result);

    private bool CanApplyReadyTransition() =>
        !_isCompleted &&
        !_isIngressUnusable &&
        HandshakeState == BsvHandshakeState.Ready;

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
