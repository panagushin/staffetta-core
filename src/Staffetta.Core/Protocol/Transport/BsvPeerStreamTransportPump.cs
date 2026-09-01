using System.Buffers;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Relay;
using Staffetta.Core.Protocol.Sessions;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Protocol.Transport;

/// <summary>
/// Advances one BSV peer session over a duplex stream by one bounded asynchronous operation.
/// </summary>
/// <remarks>
/// This type is single-consumer. It deliberately provides no background actor or command queue.
/// The caller owns scheduling and may start commands only between completed steps.
/// </remarks>
internal sealed class BsvPeerStreamTransportPump : IAsyncDisposable
{
    private readonly Stream _stream;
    private readonly BsvPeerSessionIngressAdapter _session;
    private readonly BsvPeerLocalHandshakeConfiguration _localHandshake;
    private readonly BsvPeerStreamTransportOptions _options;
    private readonly BsvPeerStreamIngressDriver _ingress;
    private readonly BsvPeerStreamEgressDriver _egress;
    private readonly BsvPeerSessionOutputDispatcher _outputs;
    private bool _isStepping;
    private bool _isStartingRead;
    private bool _dependencyReentryDetected;
    private bool _deferReentryUntilCommittedFactsDrain;
    private bool _isStarted;
    private bool _isTerminal;
    private bool _resourcesReleased;
    private bool _isDisposed;
    private BsvPeerTransportStepResult _terminalResult;

    internal BsvPeerStreamTransportPump(
        Stream stream,
        ReadOnlySpan<byte> expectedNetworkMagic,
        ulong maximumInboundPayloadLength,
        int minimumPeerProtocolVersion,
        BsvPeerLocalHandshakeConfiguration localHandshake,
        ILegacyTransactionSink transactionSink,
        IBsvTransactionPayloadSourceProvider transactionSources,
        IBsvPeerSessionFactSink factSink,
        BsvPeerStreamTransportOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanWrite)
        {
            throw new ArgumentException("The peer stream must be readable and writable.", nameof(stream));
        }

        _stream = stream;
        _localHandshake = localHandshake ?? throw new ArgumentNullException(nameof(localHandshake));
        ArgumentNullException.ThrowIfNull(transactionSources);
        ArgumentNullException.ThrowIfNull(factSink);
        _options = options ?? new BsvPeerStreamTransportOptions();
        _session = new BsvPeerSessionIngressAdapter(
            expectedNetworkMagic,
            maximumInboundPayloadLength,
            minimumPeerProtocolVersion,
            transactionSink ?? throw new ArgumentNullException(nameof(transactionSink)));
        _ingress = new BsvPeerStreamIngressDriver(
            _stream,
            _session,
            _options.ReadBufferLength);
        _egress = new BsvPeerStreamEgressDriver(
            _stream,
            transactionSources,
            _options.TransactionBufferLength,
            _options.MaximumWriteLength);
        _outputs = new BsvPeerSessionOutputDispatcher(_session, _localHandshake, factSink);
    }

    internal bool HasLocalWork =>
        !_isTerminal &&
        (_deferReentryUntilCommittedFactsDrain ||
            _dependencyReentryDetected ||
            _session.HandshakeState == BsvHandshakeState.Terminal ||
            _ingress.HasBufferedInput ||
            _outputs.HasStagedOutputs ||
            _session.HasPendingOutputs ||
            _session.PendingHandshakeEgressIntentCount != 0 ||
            _session.EgressState != BsvPeerSessionEgressState.Idle ||
            _egress.HasTransactionSource);

    internal BsvHandshakeState HandshakeState => _session.HandshakeState;

    internal BsvHandshakeTerminalReason HandshakeTerminalReason =>
        _session.HandshakeTerminalReason;

    internal BsvTransactionBroadcastState BroadcastState => _session.BroadcastState;

    internal BsvTransactionFetchState FetchState => _session.FetchState;

    internal bool TryGetReadyPeerSnapshot(out BsvPeerReadySnapshot snapshot)
    {
        snapshot = default;
        if (_session.HandshakeState != BsvHandshakeState.Ready || !_session.HasPeerVersion)
        {
            return false;
        }

        snapshot = new BsvPeerReadySnapshot(
            _session.PeerProtocolVersion,
            _session.EffectivePeerMaximumReceivePayloadLength,
            _session.HasPeerProtoconf);
        return true;
    }

    internal BsvPeerTransportStepResult TerminalResult => _terminalResult;

    internal bool IsTerminal => _isTerminal;

    internal bool CanApplyActorCommand => CanStartRelayCommand();

    internal bool IsFramePartial => _ingress.IsFramePartial;

    internal OperationStatus StartHandshake()
    {
        ThrowIfDisposed();
        if (RejectCommandReentry())
        {
            return OperationStatus.InvalidData;
        }

        if (!CanStartCommand() || _isStarted)
        {
            return OperationStatus.InvalidData;
        }

        var status = _session.StartHandshake(_localHandshake.Nonce);
        if (status == OperationStatus.Done)
        {
            _isStarted = true;
        }

        return status;
    }

    internal OperationStatus StartBroadcast(Hash256 transactionId)
    {
        ThrowIfDisposed();
        if (RejectCommandReentry())
        {
            return OperationStatus.InvalidData;
        }

        return CanStartRelayCommand()
            ? _session.StartBroadcast(transactionId)
            : OperationStatus.InvalidData;
    }

    internal OperationStatus StartFetch(Hash256 transactionId)
    {
        ThrowIfDisposed();
        if (RejectCommandReentry())
        {
            return OperationStatus.InvalidData;
        }

        return CanStartRelayCommand()
            ? _session.StartFetch(transactionId)
            : OperationStatus.InvalidData;
    }

    internal async ValueTask<BsvPeerTransportStepResult> StepAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (_isStepping)
        {
            _dependencyReentryDetected = true;
            throw new InvalidOperationException("Peer transport steps cannot overlap or re-enter.");
        }

        if (_isTerminal)
        {
            return _terminalResult;
        }

        if (!_isStarted)
        {
            return await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
        }

        _isStepping = true;
        try
        {
            var local = await DriveLocalAsync(cancellationToken).ConfigureAwait(false);
            if (local.Kind == BsvPeerTransportDriveKind.Progress)
            {
                return local.StepResult;
            }

            if (local.Kind == BsvPeerTransportDriveKind.Terminal)
            {
                return local.StepResult;
            }

            var read = BeginPeerReadCore(cancellationToken);
            return await ApplyPeerReadCoreAsync(read, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _isStepping = false;
        }
    }

    internal async ValueTask<BsvPeerTransportDriveResult> StepLocalAsync(
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (_isStepping)
        {
            _dependencyReentryDetected = true;
            throw new InvalidOperationException("Peer transport steps cannot overlap or re-enter.");
        }

        if (_isTerminal)
        {
            return BsvPeerTransportDriveResult.Terminal(_terminalResult);
        }

        if (!_isStarted)
        {
            var terminal = await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
            return BsvPeerTransportDriveResult.Terminal(terminal);
        }

        _isStepping = true;
        try
        {
            return await DriveLocalAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _isStepping = false;
        }
    }

    internal async ValueTask<bool> TryDrainCommittedFactAsync()
    {
        ThrowIfDisposed();
        if (_isStepping || _isTerminal)
        {
            return false;
        }

        _isStepping = true;
        try
        {
            if (_session.EgressState == BsvPeerSessionEgressState.Complete)
            {
                var committed = await CommitEgressAsync().ConfigureAwait(false);
                return committed.Kind == BsvPeerTransportStepKind.Progress;
            }

            if (_session.EgressState != BsvPeerSessionEgressState.Idle)
            {
                return false;
            }

            if (!_outputs.HasStagedOutputs &&
                _session.HasPendingOutputs &&
                !_outputs.TryStageOutputs())
            {
                await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
                return false;
            }

            if (!_outputs.HasStagedOutputs)
            {
                return false;
            }

            var dispatch = _outputs.DispatchNext();
            if (dispatch.Kind != BsvPeerSessionOutputDispatchKind.FactPending)
            {
                return false;
            }

            var result = await ProcessNextOutputAsync(CancellationToken.None).ConfigureAwait(false);
            return result.Kind == BsvPeerTransportStepKind.Progress;
        }
        finally
        {
            _isStepping = false;
        }
    }

    internal BsvPeerStreamReadOperation BeginPeerRead(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (_isStepping)
        {
            throw new InvalidOperationException("The peer is not ready to begin a read.");
        }

        return BeginPeerReadCore(cancellationToken);
    }

    private BsvPeerStreamReadOperation BeginPeerReadCore(CancellationToken cancellationToken)
    {
        if (_isTerminal || _isStartingRead || _ingress.HasPendingRead ||
            _ingress.HasBufferedInput)
        {
            throw new InvalidOperationException("The peer is not ready to begin a read.");
        }

        _isStartingRead = true;
        try
        {
            return _ingress.BeginRead(cancellationToken);
        }
        finally
        {
            _isStartingRead = false;
        }
    }

    internal async ValueTask<BsvPeerTransportStepResult> ApplyPeerReadAsync(
        BsvPeerStreamReadOperation read,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (_isStepping || !_ingress.IsPendingRead(read))
        {
            throw new InvalidOperationException("The peer read does not belong to this pump.");
        }

        _isStepping = true;
        try
        {
            return await ApplyPeerReadCoreAsync(read, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _isStepping = false;
        }
    }

    private async ValueTask<BsvPeerTransportDriveResult> DriveLocalAsync(
        CancellationToken cancellationToken)
    {
            if (_dependencyReentryDetected)
            {
                return ToDrive(await TerminateForReentryAsync().ConfigureAwait(false));
            }

            if (_session.EgressState is BsvPeerSessionEgressState.Active)
            {
                var pending = _session.PendingEgressSegment;
                if (!pending.IsEmpty)
                {
                    return ToDrive(await WritePendingSegmentAsync(pending, cancellationToken).ConfigureAwait(false));
                }

                if (_egress.HasTransactionSource && !_egress.TransactionPayloadEnded)
                {
                    return ToDrive(await ReadTransactionChunkAsync(cancellationToken).ConfigureAwait(false));
                }

                return ToDrive(await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.TransactionSourceContractViolation).ConfigureAwait(false));
            }

            if (_session.EgressState == BsvPeerSessionEgressState.Complete)
            {
                return ToDrive(await CommitEgressAsync().ConfigureAwait(false));
            }

            if (_session.EgressState is BsvPeerSessionEgressState.Faulted or
                BsvPeerSessionEgressState.Aborted or BsvPeerSessionEgressState.Disposed)
            {
                return ToDrive(await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false));
            }

            if (!_outputs.HasStagedOutputs &&
                _session.HasPendingOutputs &&
                !_outputs.TryStageOutputs())
            {
                return ToDrive(await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false));
            }

            if (_outputs.HasStagedOutputs)
            {
                return ToDrive(await ProcessNextOutputAsync(cancellationToken).ConfigureAwait(false));
            }

            if (_deferReentryUntilCommittedFactsDrain && !_session.HasPendingOutputs)
            {
                return ToDrive(await TerminateForReentryAsync().ConfigureAwait(false));
            }

            if (_session.HandshakeState == BsvHandshakeState.Terminal)
            {
                return ToDrive(await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.HandshakeTerminated).ConfigureAwait(false));
            }

            if (_ingress.HasBufferedInput)
            {
                return ToDrive(await ConsumeBufferedInputAsync().ConfigureAwait(false));
            }

            return BsvPeerTransportDriveResult.NeedsPeerRead;
    }

    public async ValueTask DisposeAsync()
    {
        if (_isDisposed)
        {
            return;
        }

        if (_isStepping)
        {
            _dependencyReentryDetected = true;
            throw new InvalidOperationException("Dispose cannot overlap an active peer transport step.");
        }

        _isDisposed = true;
        await ReleaseResourcesAsync().ConfigureAwait(false);
    }

    private bool CanStartCommand() =>
        !_isStepping &&
        !_isStartingRead &&
        !_dependencyReentryDetected &&
        !_isTerminal &&
        !_isDisposed &&
        !_deferReentryUntilCommittedFactsDrain &&
        !_ingress.HasBufferedInput &&
        !_ingress.IsFramePartial &&
        !_outputs.HasStagedOutputs &&
        !_session.HasPendingOutputs &&
        _session.PendingHandshakeEgressIntentCount == 0 &&
        _session.EgressState == BsvPeerSessionEgressState.Idle &&
        !_egress.HasTransactionSource;

    private bool CanStartRelayCommand() =>
        _session.HandshakeState == BsvHandshakeState.Ready && CanStartCommand();

    private async ValueTask<BsvPeerTransportStepResult> ProcessNextOutputAsync(
        CancellationToken cancellationToken)
    {
        var dispatch = _outputs.DispatchNext();
        if (dispatch.Kind == BsvPeerSessionOutputDispatchKind.FactPending)
        {
            try
            {
                await _outputs.DeliverFactAsync(dispatch).ConfigureAwait(false);
                if (_dependencyReentryDetected)
                {
                    return await TerminateForReentryAsync().ConfigureAwait(false);
                }
            }
            catch
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.FactSinkFailure).ConfigureAwait(false);
            }

            if (!_outputs.TryCommit(dispatch))
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
            }

            return BsvPeerTransportStepResult.Progress;
        }

        if (dispatch.Kind == BsvPeerSessionOutputDispatchKind.TransactionRequested)
        {
            var output = dispatch.TransactionRequest;
            bool hasSource;
            try
            {
                hasSource = await _egress.OpenTransactionSourceAsync(
                    output.TransactionId,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Canceled,
                    BsvPeerTransportTerminalReason.Canceled).ConfigureAwait(false);
            }
            catch
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.TransactionSourceFailure).ConfigureAwait(false);
            }

            if (!hasSource)
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.TransactionSourceUnavailable).ConfigureAwait(false);
            }

            if (_dependencyReentryDetected)
            {
                return await TerminateForReentryAsync().ConfigureAwait(false);
            }

            Hash256 sourceTransactionId;
            try
            {
                sourceTransactionId = _egress.SnapshotTransactionId();
            }
            catch
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.TransactionSourceFailure).ConfigureAwait(false);
            }

            if (_dependencyReentryDetected)
            {
                return await TerminateForReentryAsync().ConfigureAwait(false);
            }

            ulong sourceLength;
            try
            {
                sourceLength = _egress.SnapshotTransactionLength();
            }
            catch
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.TransactionSourceFailure).ConfigureAwait(false);
            }

            if (_dependencyReentryDetected)
            {
                return await TerminateForReentryAsync().ConfigureAwait(false);
            }

            if (sourceTransactionId != output.TransactionId ||
                _session.PlanTransactionEgress(output, sourceLength, sourceTransactionId) !=
                    OperationStatus.Done)
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.TransactionSourceContractViolation).ConfigureAwait(false);
            }

            if (!_outputs.TryCommit(dispatch))
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
            }

            return BsvPeerTransportStepResult.Progress;
        }

        if (dispatch.Kind == BsvPeerSessionOutputDispatchKind.InvalidData)
        {
            return await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
        }

        return BsvPeerTransportStepResult.Progress;
    }

    private async ValueTask<BsvPeerTransportStepResult> WritePendingSegmentAsync(
        MessageFrameWriteSegment pending,
        CancellationToken cancellationToken)
    {
        BsvPeerStreamPendingWrite write;
        try
        {
            write = await _egress.WritePendingPrefixAsync(pending, cancellationToken)
                .ConfigureAwait(false);
            if (_dependencyReentryDetected)
            {
                return await TerminateForReentryAsync().ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return await TerminateAsync(
                BsvPeerTransportStepKind.Canceled,
                BsvPeerTransportTerminalReason.Canceled).ConfigureAwait(false);
        }
        catch
        {
            return await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                BsvPeerTransportTerminalReason.TransportWriteFailure).ConfigureAwait(false);
        }

        if (BsvPeerStreamEgressDriver.AcknowledgeWrittenPrefix(_session, write) !=
            OperationStatus.Done)
        {
            return await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                !_egress.HasTransactionSource
                    ? BsvPeerTransportTerminalReason.ProtocolViolation
                    : BsvPeerTransportTerminalReason.TransactionHashMismatch).ConfigureAwait(false);
        }

        return BsvPeerTransportStepResult.Progress;
    }

    private async ValueTask<BsvPeerTransportStepResult> ReadTransactionChunkAsync(
        CancellationToken cancellationToken)
    {
        BsvPeerStreamTransactionRead read;
        try
        {
            read = await _egress.ReadTransactionChunkAsync(cancellationToken).ConfigureAwait(false);
            if (_dependencyReentryDetected)
            {
                return await TerminateForReentryAsync().ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return await TerminateAsync(
                BsvPeerTransportStepKind.Canceled,
                BsvPeerTransportTerminalReason.Canceled).ConfigureAwait(false);
        }
        catch
        {
            return await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                BsvPeerTransportTerminalReason.TransactionSourceFailure).ConfigureAwait(false);
        }

        var status = read.IsEndOfPayload
            ? _egress.EndTransactionPayload(_session)
            : _egress.AcceptTransactionRead(_session, read);
        if (status != OperationStatus.Done)
        {
            return await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                BsvPeerTransportTerminalReason.TransactionSourceContractViolation).ConfigureAwait(false);
        }

        return BsvPeerTransportStepResult.Progress;
    }

    private async ValueTask<BsvPeerTransportStepResult> CommitEgressAsync()
    {
        var wasTransaction = _egress.HasTransactionSource;
        var status = await _egress.CommitAsync(_session).ConfigureAwait(false);
        if (status == OperationStatus.DestinationTooSmall)
        {
            return _outputs.TryStageOutputs()
                ? BsvPeerTransportStepResult.Progress
                : await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
        }

        if (status != OperationStatus.Done)
        {
            return await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                wasTransaction
                    ? BsvPeerTransportTerminalReason.TransactionHashMismatch
                    : BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
        }

        if (wasTransaction)
        {
            if (_dependencyReentryDetected)
            {
                _dependencyReentryDetected = false;
                _deferReentryUntilCommittedFactsDrain = true;
            }
        }

        return BsvPeerTransportStepResult.Progress;
    }

    private async ValueTask<BsvPeerTransportStepResult> ConsumeBufferedInputAsync()
    {
        while (_ingress.HasBufferedInput)
        {
            OperationStatus status;
            int consumed;
            try
            {
                status = _ingress.ConsumeBufferedInput(out consumed);
                if (_dependencyReentryDetected)
                {
                    return await TerminateForReentryAsync().ConfigureAwait(false);
                }
            }
            catch
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
            }

            if (!_ingress.TryCommitConsume(status, consumed))
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
            }

            if (status == OperationStatus.InvalidData)
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
            }

            if (_session.HasPendingOutputs || _session.PendingHandshakeEgressIntentCount != 0)
            {
                if (_session.HasPendingOutputs && !_outputs.TryStageOutputs())
                {
                    return await TerminateAsync(
                        BsvPeerTransportStepKind.Faulted,
                        BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
                }

                return BsvPeerTransportStepResult.Progress;
            }

            if (consumed == 0)
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
            }

            if (status is not OperationStatus.Done and not OperationStatus.NeedMoreData)
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
            }
        }

        return BsvPeerTransportStepResult.Progress;
    }

    private async ValueTask<BsvPeerTransportStepResult> ApplyPeerReadCoreAsync(
        BsvPeerStreamReadOperation read,
        CancellationToken cancellationToken)
    {
        int bytesRead;
        try
        {
            bytesRead = await read.Completion.ConfigureAwait(false);
            if (_dependencyReentryDetected)
            {
                return await TerminateForReentryAsync().ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _ingress.TryAbandonRead(read);
            return await TerminateAsync(
                BsvPeerTransportStepKind.Canceled,
                BsvPeerTransportTerminalReason.Canceled).ConfigureAwait(false);
        }
        catch
        {
            _ingress.TryAbandonRead(read);
            return await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                BsvPeerTransportTerminalReason.TransportReadFailure).ConfigureAwait(false);
        }

        if (bytesRead < 0)
        {
            _ingress.TryAbandonRead(read);
            return await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                BsvPeerTransportTerminalReason.TransportReadFailure).ConfigureAwait(false);
        }

        if (bytesRead == 0)
        {
            if (!_ingress.TryAbandonRead(read))
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.TransportReadFailure).ConfigureAwait(false);
            }

            OperationStatus status;
            try
            {
                status = _ingress.CompleteEndOfInput();
            }
            catch
            {
                status = OperationStatus.InvalidData;
            }

            return await TerminateAsync(
                status == OperationStatus.Done
                    ? BsvPeerTransportStepKind.PeerClosed
                    : BsvPeerTransportStepKind.Faulted,
                status == OperationStatus.Done
                    ? BsvPeerTransportTerminalReason.PeerClosed
                    : BsvPeerTransportTerminalReason.TruncatedInput).ConfigureAwait(false);
        }

        if (!_ingress.TryCommitRead(read, bytesRead))
        {
            return await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                BsvPeerTransportTerminalReason.TransportReadFailure).ConfigureAwait(false);
        }

        return BsvPeerTransportStepResult.Progress;
    }

    private static BsvPeerTransportDriveResult ToDrive(BsvPeerTransportStepResult result) =>
        result.Kind == BsvPeerTransportStepKind.Progress
            ? BsvPeerTransportDriveResult.Progress
            : BsvPeerTransportDriveResult.Terminal(result);

    private async ValueTask<BsvPeerTransportStepResult> TerminateAsync(
        BsvPeerTransportStepKind kind,
        BsvPeerTransportTerminalReason reason)
    {
        if (!_isTerminal)
        {
            _isTerminal = true;
            _terminalResult = new BsvPeerTransportStepResult(kind, reason);
            await ReleaseResourcesAsync().ConfigureAwait(false);
        }

        return _terminalResult;
    }

    private async ValueTask ReleaseResourcesAsync()
    {
        if (_resourcesReleased)
        {
            return;
        }

        _resourcesReleased = true;
        await _egress.ReleaseTransactionSourceAsync().ConfigureAwait(false);
        try
        {
            _session.Dispose();
        }
        catch
        {
            // Terminal cleanup preserves the primary transport result.
        }

        if (!_options.LeaveOpen)
        {
            try
            {
                await _stream.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
                // Terminal cleanup preserves the primary transport result.
            }
        }
    }

    private bool RejectCommandReentry()
    {
        if (!_isStepping && !_isStartingRead)
        {
            return false;
        }

        _dependencyReentryDetected = true;
        return true;
    }

    private ValueTask<BsvPeerTransportStepResult> TerminateForReentryAsync() =>
        TerminateAsync(
            BsvPeerTransportStepKind.Faulted,
            BsvPeerTransportTerminalReason.DependencyReentry);

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_isDisposed, this);
}
