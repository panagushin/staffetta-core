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
/// more input is consumed. Draining a send intent never acknowledges a transport write; handshake
/// and relay write facts enter the session only through its owned egress planner after the exact
/// frame is fully acknowledged.
/// Transaction sink callbacks remain provisional until both the transaction structure and its
/// enclosing frame are validated.
/// The transport-write planner and acknowledgements are internal. External library consumers
/// can use <see cref="BsvPeerObservationSession"/> for a curated observation driver, or standalone
/// codecs and state machines rather than treating this adapter as a complete public session driver.
/// </remarks>
public sealed class BsvPeerSessionIngressAdapter :
    IMessageIngressSink,
    IMessageIngressAdmissionPolicy,
    IMessageIngressPayloadHashPolicy,
    IBsvPeerSessionEgressCompletionOwner,
    IDisposable
{
    /// <summary>Maximum inventory vectors admitted by this session's BSV interop profile.</summary>
    public const ulong MaximumInventoryCount = BsvPeerSessionFrameProcessor.MaximumInventoryCount;

    /// <summary>Resource-policy bound on ignored payloads, not a network consensus limit.</summary>
    public const ulong MaximumIgnoredPayloadLength =
        BsvPeerSessionFrameProcessor.MaximumIgnoredPayloadLength;

    /// <summary>Largest encoded inventory payload admitted by this session's interop profile.</summary>
    public const ulong MaximumInventoryPayloadLength =
        BsvPeerSessionFrameProcessor.MaximumInventoryPayloadLength;

    private readonly BsvPeerSessionFrameProcessor _processor;
    private readonly MessageIngressStateMachine _ingress;
    private readonly BsvPeerSessionEgressPlanner _egress;

    private bool _isOperating;
    private bool _callbackReentryDetected;
    private bool _isIngressUnusable;
    private bool _isCompleted;
    private bool _isEgressDisposed;
    private bool _isDisposed;

    /// <summary>Creates a single-consumer session with caller-selected network and resource admission bounds.</summary>
    /// <param name="expectedNetworkMagic">Exactly four network-magic bytes, copied during construction.</param>
    /// <param name="maximumPayloadLength">Maximum declared frame payload admitted without size-based allocation.</param>
    /// <param name="minimumPeerProtocolVersion">Lowest accepted peer version number.</param>
    /// <param name="transactionSink">Receives provisional transaction callbacks; commits require full frame validation.</param>
    public BsvPeerSessionIngressAdapter(
        ReadOnlySpan<byte> expectedNetworkMagic,
        ulong maximumPayloadLength,
        int minimumPeerProtocolVersion,
        ILegacyTransactionSink transactionSink)
        : this(expectedNetworkMagic, maximumPayloadLength, minimumPeerProtocolVersion, transactionSink, null)
    {
    }

    internal BsvPeerSessionIngressAdapter(
        ReadOnlySpan<byte> expectedNetworkMagic,
        ulong maximumPayloadLength,
        int minimumPeerProtocolVersion,
        ILegacyTransactionSink transactionSink,
        BsvPeerObservationBuffers? observations)
    {
        _processor = new BsvPeerSessionFrameProcessor(
            minimumPeerProtocolVersion,
            new GuardedTransactionSink(
                this,
                transactionSink ?? throw new ArgumentNullException(nameof(transactionSink))),
            observations);
        _ingress = new MessageIngressStateMachine(
            expectedNetworkMagic,
            maximumPayloadLength,
            _processor,
            _processor,
            _processor);
        _egress = new BsvPeerSessionEgressPlanner(expectedNetworkMagic, this);
    }

    /// <summary>Current handshake state; reading it performs no I/O.</summary>
    public BsvHandshakeState HandshakeState => _processor.HandshakeState;

    /// <summary>Handshake termination reason, or none before termination.</summary>
    public BsvHandshakeTerminalReason HandshakeTerminalReason =>
        _processor.HandshakeTerminalReason;

    /// <summary>Whether a peer version payload has passed frame and handshake admission.</summary>
    public bool HasPeerVersion => _processor.HasPeerVersion;

    /// <summary>Admitted peer version, meaningful when <see cref="HasPeerVersion"/> is true.</summary>
    public int PeerProtocolVersion => _processor.PeerProtocolVersion;

    /// <summary>Nonce from the admitted peer version payload.</summary>
    public ulong PeerNonce => _processor.PeerNonce;

    /// <summary>Whether a validated peer verack has been observed.</summary>
    public bool HasPeerVerack => _processor.HasPeerVerack;

    /// <summary>Whether a peer protoconf has been admitted.</summary>
    public bool HasPeerProtoconf => _processor.HasPeerProtoconf;

    /// <summary>Peer receive bound accepted by the handshake, including its legacy default floor.</summary>
    public uint EffectivePeerMaximumReceivePayloadLength =>
        _processor.EffectivePeerMaximumReceivePayloadLength;

    /// <summary>Current broadcast state for the session's target transaction.</summary>
    public BsvTransactionBroadcastState BroadcastState => _processor.BroadcastState;

    /// <summary>Broadcast termination reason, independent of whether earlier wire facts were committed.</summary>
    public BsvTransactionBroadcastTerminalReason BroadcastTerminalReason =>
        _processor.BroadcastTerminalReason;

    /// <summary>Broadcast target txid, assigned by <see cref="StartBroadcast"/>.</summary>
    public Hash256 TargetTransactionId => _processor.TargetTransactionId;

    /// <summary>Whether the target inventory announcement was transport-committed.</summary>
    public bool IsAnnounced => _processor.IsAnnounced;

    /// <summary>Whether a matching peer getdata request was admitted by the broadcast flow.</summary>
    public bool WasRequestedByPeer => _processor.WasRequestedByPeer;

    /// <summary>Whether target transaction bytes were transport-committed with matching identity; not mining acceptance.</summary>
    public bool IsSentToPeer => _processor.IsSentToPeer;

    /// <summary>Whether peer inventory echoed the broadcast target; not proof of independent propagation.</summary>
    public bool WasObservedFromPeer => _processor.WasObservedFromPeer;

    /// <summary>Whether a peer rejection was correlated to the broadcast transaction.</summary>
    public bool IsRejected => _processor.IsRejected;

    /// <summary>Current fetch state for the requested transaction.</summary>
    public BsvTransactionFetchState FetchState => _processor.FetchState;

    /// <summary>Fetch termination reason, or none before termination.</summary>
    public BsvTransactionFetchTerminalReason FetchTerminalReason => _processor.FetchTerminalReason;

    /// <summary>Fetch target txid, assigned by <see cref="StartFetch"/>.</summary>
    public Hash256 FetchTargetTransactionId => _processor.FetchTargetTransactionId;

    /// <summary>Number of handshake outputs awaiting drainage.</summary>
    public int PendingHandshakeOutputCount => _processor.PendingHandshakeOutputCount;

    internal int PendingHandshakeEgressIntentCount =>
        _processor.PendingHandshakeEgressIntentCount;

    /// <summary>Number of broadcast intents or facts awaiting drainage.</summary>
    public int PendingBroadcastOutputCount => _processor.PendingBroadcastOutputCount;

    /// <summary>Number of fetch intents or facts awaiting drainage.</summary>
    public int PendingFetchOutputCount => _processor.PendingFetchOutputCount;

    internal int PendingMonetaryValidationCount =>
        _processor.PendingMonetaryValidationCount;

    /// <summary>Whether outputs remain, including monetary verdicts drained by the internal transport integration.</summary>
    public bool HasPendingOutputs => _processor.HasPendingOutputs;

    /// <summary>Begins an outbound handshake; a queued version intent is not a committed wire write.</summary>
    /// <returns>Done on acceptance, DestinationTooSmall while outputs or egress intents remain, otherwise InvalidData.</returns>
    public OperationStatus StartHandshake(ulong localNonce)
    {
        ThrowIfUnavailable();
        if (_isCompleted ||
            _isIngressUnusable ||
            HasPendingOutputs ||
            PendingHandshakeEgressIntentCount != 0)
        {
            return HasPendingOutputs || PendingHandshakeEgressIntentCount != 0
                ? OperationStatus.DestinationTooSmall
                : OperationStatus.InvalidData;
        }

        return _processor.StartHandshake(localNonce);
    }

    /// <summary>Starts a broadcast in a ready session without providing or signing transaction bytes.</summary>
    /// <returns>Done on acceptance, DestinationTooSmall for pending outputs, or InvalidData for an unavailable flow.</returns>
    public OperationStatus StartBroadcast(Hash256 transactionId)
    {
        ThrowIfUnavailable();
        if (!CanApplyReadyTransition())
        {
            return OperationStatus.InvalidData;
        }

        if (HasPendingOutputs || PendingHandshakeEgressIntentCount != 0)
        {
            return OperationStatus.DestinationTooSmall;
        }

        return _processor.StartBroadcast(transactionId);
    }

    /// <summary>Starts waiting for peer inventory of a transaction in a ready session.</summary>
    /// <returns>Done on acceptance, DestinationTooSmall for pending outputs, or InvalidData for an unavailable flow.</returns>
    public OperationStatus StartFetch(Hash256 transactionId)
    {
        ThrowIfUnavailable();
        if (!CanApplyReadyTransition())
        {
            return OperationStatus.InvalidData;
        }

        if (HasPendingOutputs || PendingHandshakeEgressIntentCount != 0)
        {
            return OperationStatus.DestinationTooSmall;
        }

        return _processor.StartFetch(transactionId);
    }

    internal BsvPeerSessionEgressState EgressState => _egress.State;

    internal MessageFrameWriteSegment PendingEgressSegment => _egress.PendingSegment;

    internal OperationStatus PlanNextHandshakeEgress()
    {
        ThrowIfUnavailable();
        if (!CanPlanEgress(requireReady: false, out var blockedStatus))
        {
            return blockedStatus;
        }

        if (!_processor.TryPeekHandshakeEgressIntent(out var intent) ||
            intent.Kind is not BsvHandshakeOutputKind.SendVerack and
                not BsvHandshakeOutputKind.SendPong and
                not BsvHandshakeOutputKind.SendPing)
        {
            return OperationStatus.InvalidData;
        }

        return _egress.PlanHandshake(
            intent,
            EffectivePeerMaximumReceivePayloadLength,
            out _);
    }

    internal OperationStatus PlanVersionEgress(VersionPayload payload)
    {
        ThrowIfUnavailable();
        if (!CanPlanEgress(requireReady: false, out var blockedStatus))
        {
            return blockedStatus;
        }

        if (!_processor.TryPeekHandshakeEgressIntent(out var intent) ||
            intent.Kind != BsvHandshakeOutputKind.SendVersion ||
            payload.Nonce != intent.Value ||
            !payload.HasSourceAddress ||
            !payload.HasUserAgent ||
            !payload.HasStartHeight ||
            !payload.HasRelay ||
            payload.UserAgent.Length > VersionPayloadCodec.MaximumUserAgentLength ||
            payload.AssociationId.Length > VersionPayloadCodec.MaximumAssociationIdLength)
        {
            return OperationStatus.InvalidData;
        }

        return _egress.PlanVersion(intent, payload, EffectivePeerMaximumReceivePayloadLength);
    }

    internal OperationStatus PlanProtoconfEgress(
        uint maximumReceivePayloadLength,
        ReadOnlySpan<byte> streamPolicies,
        bool includeStreamPolicies)
    {
        ThrowIfUnavailable();
        if (!CanPlanEgress(requireReady: false, out var blockedStatus))
        {
            return blockedStatus;
        }

        if (!_processor.TryPeekHandshakeEgressIntent(out var intent) ||
            intent.Kind != BsvHandshakeOutputKind.SendProtoconf ||
            (!includeStreamPolicies && !streamPolicies.IsEmpty) ||
            streamPolicies.Length > ProtoconfPayloadCodec.MaximumStreamPoliciesLength)
        {
            return OperationStatus.InvalidData;
        }

        return _egress.PlanProtoconf(
            intent,
            maximumReceivePayloadLength,
            streamPolicies,
            includeStreamPolicies,
            EffectivePeerMaximumReceivePayloadLength);
    }

    internal OperationStatus PlanBroadcastEgress(
        in BsvTransactionBroadcastOutput output,
        out BsvPeerSessionOutputDisposition disposition)
    {
        ThrowIfUnavailable();
        if (!CanPlanEgress(requireReady: true, out var blockedStatus))
        {
            disposition = BsvPeerSessionOutputDisposition.Send;
            return blockedStatus;
        }

        if (!_processor.CanPlanBroadcastEgress(output))
        {
            disposition = BsvPeerSessionOutputDisposition.Send;
            return OperationStatus.InvalidData;
        }

        return _egress.PlanBroadcast(
            output,
            EffectivePeerMaximumReceivePayloadLength,
            out disposition);
    }

    internal OperationStatus PlanTransactionEgress(
        in BsvTransactionBroadcastOutput output,
        ulong payloadLength,
        Hash256 expectedTransactionId)
    {
        ThrowIfUnavailable();
        if (!CanPlanEgress(requireReady: true, out var blockedStatus))
        {
            return blockedStatus;
        }

        return _processor.CanPlanBroadcastEgress(output)
            ? _egress.PlanTransaction(
                output,
                payloadLength,
                expectedTransactionId,
                EffectivePeerMaximumReceivePayloadLength)
            : OperationStatus.InvalidData;
    }

    internal OperationStatus PlanFetchEgress(
        in BsvTransactionFetchOutput output,
        out BsvPeerSessionOutputDisposition disposition)
    {
        ThrowIfUnavailable();
        if (!CanPlanEgress(requireReady: true, out var blockedStatus))
        {
            disposition = BsvPeerSessionOutputDisposition.Send;
            return blockedStatus;
        }

        if (!_processor.CanPlanFetchEgress(output))
        {
            disposition = BsvPeerSessionOutputDisposition.Send;
            return OperationStatus.InvalidData;
        }

        return _egress.PlanFetch(
            output,
            EffectivePeerMaximumReceivePayloadLength,
            out disposition);
    }

    internal OperationStatus ProvideTransactionEgressChunk(ReadOnlyMemory<byte> chunk)
    {
        ThrowIfUnavailable();
        return CanUseEgress()
            ? _egress.ProvideTransactionChunk(chunk)
            : OperationStatus.InvalidData;
    }

    internal OperationStatus AcknowledgeEgress(
        in MessageFrameWriteSegment segment,
        int bytesWritten)
    {
        ThrowIfUnavailable();
        return CanUseEgress()
            ? _egress.Acknowledge(segment, bytesWritten)
            : OperationStatus.InvalidData;
    }

    internal OperationStatus EndTransactionEgressPayload()
    {
        ThrowIfUnavailable();
        return CanUseEgress()
            ? _egress.EndTransactionPayload()
            : OperationStatus.InvalidData;
    }

    internal OperationStatus CommitEgressCompletion()
    {
        ThrowIfUnavailable();
        if (_isCompleted || _isIngressUnusable)
        {
            return OperationStatus.InvalidData;
        }

        var status = _egress.CommitCompletion();
        if (status == OperationStatus.InvalidData)
        {
            _isIngressUnusable = true;
            TerminateSession(BsvPeerSessionTerminationCause.ExternalFailure);
        }

        return status;
    }

    internal OperationStatus AbortEgress()
    {
        ThrowIfUnavailable();
        return CanUseEgress()
            ? _egress.Abort()
            : OperationStatus.InvalidData;
    }

    /// <summary>Consumes no more than one complete wire frame.</summary>
    /// <param name="source">Borrowed wire bytes; unconsumed bytes remain caller-owned.</param>
    /// <param name="bytesConsumed">Number of bytes accepted from this call, including partial frames.</param>
    /// <returns>Done for a completed frame, NeedMoreData for partial input, DestinationTooSmall while outputs block consumption, or InvalidData for a terminal violation.</returns>
    public OperationStatus Consume(ReadOnlySpan<byte> source, out int bytesConsumed)
    {
        ThrowIfUnavailable();
        bytesConsumed = 0;
        if (PendingHandshakeEgressIntentCount != 0)
        {
            return OperationStatus.DestinationTooSmall;
        }

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
            TerminateSession(BsvPeerSessionTerminationCause.ExternalFailure);
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
            TerminateSession(BsvPeerSessionTerminationCause.WireViolation);
            if (!_processor.FrameAborted)
            {
                _processor.ApplyWireViolation();
            }

            return OperationStatus.InvalidData;
        }

        return status;
    }

    /// <summary>Copies pending handshake outputs to the caller without acknowledging any transport write.</summary>
    /// <returns>DestinationTooSmall if the batch does not fit or previous egress intents remain, Done on drainage, or InvalidData if internal intent admission fails.</returns>
    public OperationStatus DrainHandshakeOutputs(
        Span<BsvHandshakeOutput> destination,
        out int outputsWritten)
    {
        ThrowIfUnavailable();
        return _processor.DrainHandshakeOutputs(destination, out outputsWritten);
    }

    /// <summary>Copies pending broadcast intents and committed facts; draining an intent is not sending it.</summary>
    /// <returns>DestinationTooSmall without draining if the entire batch does not fit; otherwise Done.</returns>
    public OperationStatus DrainBroadcastOutputs(
        Span<BsvTransactionBroadcastOutput> destination,
        out int outputsWritten)
    {
        ThrowIfUnavailable();
        return _processor.DrainBroadcastOutputs(destination, out outputsWritten);
    }

    /// <summary>Copies pending fetch intents and facts without performing I/O.</summary>
    /// <returns>DestinationTooSmall without draining if the entire batch does not fit; otherwise Done.</returns>
    public OperationStatus DrainFetchOutputs(
        Span<BsvTransactionFetchOutput> destination,
        out int outputsWritten)
    {
        ThrowIfUnavailable();
        return _processor.DrainFetchOutputs(destination, out outputsWritten);
    }

    internal OperationStatus DrainMonetaryValidations(
        Span<BsvTransactionMonetaryValidation> destination,
        out int outputsWritten)
    {
        ThrowIfUnavailable();
        return _processor.DrainMonetaryValidations(destination, out outputsWritten);
    }

    /// <summary>Terminates peer input and aborts an incomplete frame. Drain pending outputs before calling.</summary>
    /// <returns>Done at a clean frame boundary (also on repetition), or InvalidData for truncation or unusable ingress.</returns>
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
            TerminateSession(BsvPeerSessionTerminationCause.ExternalFailure);
            throw;
        }
        finally
        {
            _isOperating = false;
        }

        if (status == OperationStatus.InvalidData)
        {
            _isIngressUnusable = true;
            TerminateSession(BsvPeerSessionTerminationCause.Disconnected);
            return status;
        }

        _isCompleted = true;
        TerminateSession(BsvPeerSessionTerminationCause.Disconnected);
        return OperationStatus.Done;
    }

    /// <summary>Terminates the session and releases hash state; may not be called from an ingress callback.</summary>
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

        TerminateSession(BsvPeerSessionTerminationCause.Disconnected);
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

    OperationStatus IBsvPeerSessionEgressCompletionOwner.ApplyEgressCompletion(
        in BsvPeerSessionEgressCompletion completion)
    {
        if (_isCompleted ||
            _isIngressUnusable ||
            _isDisposed ||
            _isEgressDisposed ||
            completion.PlanId == 0 ||
            !_egress.IsApplyingCompletion(completion))
        {
            return OperationStatus.InvalidData;
        }

        if (completion.RelayWriteCommitKind == BsvPeerSessionRelayWriteCommitKind.None)
        {
            if (!_processor.CanApplyHandshakeEgressCompletion(completion))
            {
                return OperationStatus.InvalidData;
            }

            return _processor.ApplyHandshakeEgressCompletion(completion);
        }

        if (!CanApplyReadyTransition())
        {
            return OperationStatus.InvalidData;
        }

        if (HasPendingOutputs)
        {
            return OperationStatus.DestinationTooSmall;
        }

        if (!_processor.CanApplyEgressCompletion(completion))
        {
            return OperationStatus.InvalidData;
        }

        return _processor.ApplyEgressCompletion(completion);
    }

    private bool CanApplyReadyTransition() =>
        !_isCompleted &&
        !_isIngressUnusable &&
        HandshakeState == BsvHandshakeState.Ready;

    private bool CanPlanEgress(bool requireReady, out OperationStatus blockedStatus)
    {
        blockedStatus = OperationStatus.InvalidData;
        if (!CanUseEgress() ||
            (requireReady &&
                (!CanApplyReadyTransition() || PendingHandshakeEgressIntentCount != 0)))
        {
            return false;
        }

        if (HasPendingOutputs)
        {
            blockedStatus = OperationStatus.DestinationTooSmall;
            return false;
        }

        return true;
    }

    private bool CanUseEgress() =>
        !_isCompleted && !_isIngressUnusable && !_isEgressDisposed;

    private void TerminateSession(BsvPeerSessionTerminationCause cause)
    {
        _processor.Terminate(cause);
        if (!_isEgressDisposed)
        {
            _egress.Dispose();
            _isEgressDisposed = true;
        }
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

    internal void RejectCallbackReentry() => ThrowIfUnavailable();

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
