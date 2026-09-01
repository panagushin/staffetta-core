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
    private readonly IBsvTransactionPayloadSourceProvider _transactionSources;
    private readonly IBsvPeerSessionFactSink _factSink;
    private readonly BsvPeerStreamTransportOptions _options;
    private readonly BsvPeerStreamIngressDriver _ingress;
    private readonly byte[] _transactionBuffer;
    private readonly BsvHandshakeOutput[] _handshakeOutputs =
        new BsvHandshakeOutput[BsvHandshakeStateMachine.MaximumOutputCount];
    private readonly BsvTransactionBroadcastOutput[] _broadcastOutputs =
        new BsvTransactionBroadcastOutput[BsvTransactionBroadcastStateMachine.MaximumOutputCount];
    private readonly BsvTransactionFetchOutput[] _fetchOutputs =
        new BsvTransactionFetchOutput[BsvTransactionFetchStateMachine.MaximumOutputCount];

    private IBsvTransactionPayloadSource? _transactionSource;
    private int _handshakeOutputIndex;
    private int _handshakeOutputCount;
    private int _broadcastOutputIndex;
    private int _broadcastOutputCount;
    private int _fetchOutputIndex;
    private int _fetchOutputCount;
    private ulong _transactionLength;
    private ulong _transactionBytesRead;
    private bool _transactionPayloadEnded;
    private bool _isStepping;
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
        _transactionSources = transactionSources ??
            throw new ArgumentNullException(nameof(transactionSources));
        _factSink = factSink ?? throw new ArgumentNullException(nameof(factSink));
        _options = options ?? new BsvPeerStreamTransportOptions();
        _transactionBuffer = new byte[_options.TransactionBufferLength];
        _session = new BsvPeerSessionIngressAdapter(
            expectedNetworkMagic,
            maximumInboundPayloadLength,
            minimumPeerProtocolVersion,
            transactionSink ?? throw new ArgumentNullException(nameof(transactionSink)));
        _ingress = new BsvPeerStreamIngressDriver(
            _stream,
            _session,
            _options.ReadBufferLength);
    }

    internal bool HasLocalWork =>
        !_isTerminal &&
        (_deferReentryUntilCommittedFactsDrain ||
            _session.HandshakeState == BsvHandshakeState.Terminal ||
            _ingress.HasBufferedInput ||
            HasStagedOutputs ||
            _session.HasPendingOutputs ||
            _session.PendingHandshakeEgressIntentCount != 0 ||
            _session.EgressState != BsvPeerSessionEgressState.Idle ||
            _transactionSource is not null);

    internal BsvHandshakeState HandshakeState => _session.HandshakeState;

    internal BsvHandshakeTerminalReason HandshakeTerminalReason =>
        _session.HandshakeTerminalReason;

    internal BsvTransactionBroadcastState BroadcastState => _session.BroadcastState;

    internal BsvTransactionFetchState FetchState => _session.FetchState;

    internal BsvPeerTransportStepResult TerminalResult => _terminalResult;

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

        return CanStartCommand() ? _session.StartBroadcast(transactionId) : OperationStatus.InvalidData;
    }

    internal OperationStatus StartFetch(Hash256 transactionId)
    {
        ThrowIfDisposed();
        if (RejectCommandReentry())
        {
            return OperationStatus.InvalidData;
        }

        return CanStartCommand() ? _session.StartFetch(transactionId) : OperationStatus.InvalidData;
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
            if (_session.EgressState is BsvPeerSessionEgressState.Active)
            {
                var pending = _session.PendingEgressSegment;
                if (!pending.IsEmpty)
                {
                    return await WritePendingSegmentAsync(pending, cancellationToken).ConfigureAwait(false);
                }

                if (_transactionSource is not null && !_transactionPayloadEnded)
                {
                    return await ReadTransactionChunkAsync(cancellationToken).ConfigureAwait(false);
                }

                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.TransactionSourceContractViolation).ConfigureAwait(false);
            }

            if (_session.EgressState == BsvPeerSessionEgressState.Complete)
            {
                return await CommitEgressAsync().ConfigureAwait(false);
            }

            if (_session.EgressState is BsvPeerSessionEgressState.Faulted or
                BsvPeerSessionEgressState.Aborted or BsvPeerSessionEgressState.Disposed)
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
            }

            if (!HasStagedOutputs && _session.HasPendingOutputs && !TryStageOutputs())
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
            }

            if (HasStagedOutputs)
            {
                return await ProcessNextOutputAsync(cancellationToken).ConfigureAwait(false);
            }

            if (_deferReentryUntilCommittedFactsDrain && !_session.HasPendingOutputs)
            {
                return await TerminateForReentryAsync().ConfigureAwait(false);
            }

            if (_session.HandshakeState == BsvHandshakeState.Terminal)
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.HandshakeTerminated).ConfigureAwait(false);
            }

            if (_ingress.HasBufferedInput)
            {
                return await ConsumeBufferedInputAsync().ConfigureAwait(false);
            }

            return await ReadFromPeerAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _isStepping = false;
        }
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

    private bool HasStagedOutputs =>
        _handshakeOutputIndex != _handshakeOutputCount ||
        _broadcastOutputIndex != _broadcastOutputCount ||
        _fetchOutputIndex != _fetchOutputCount;

    private bool CanStartCommand() =>
        !_isStepping &&
        !_isTerminal &&
        !_isDisposed &&
        !_deferReentryUntilCommittedFactsDrain &&
        !_ingress.HasBufferedInput &&
        !_ingress.IsFramePartial &&
        !HasStagedOutputs &&
        !_session.HasPendingOutputs &&
        _session.PendingHandshakeEgressIntentCount == 0 &&
        _session.EgressState == BsvPeerSessionEgressState.Idle &&
        _transactionSource is null;

    private bool TryStageOutputs()
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

    private async ValueTask<BsvPeerTransportStepResult> ProcessNextOutputAsync(
        CancellationToken cancellationToken)
    {
        if (_handshakeOutputIndex != _handshakeOutputCount)
        {
            var output = _handshakeOutputs[_handshakeOutputIndex];
            if (IsHandshakeFact(output.Kind))
            {
                try
                {
                    await _factSink.OnHandshakeFactAsync(output, CancellationToken.None).ConfigureAwait(false);
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

                AdvanceHandshakeOutput();
                return BsvPeerTransportStepResult.Progress;
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
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
            }

            AdvanceHandshakeOutput();
            return BsvPeerTransportStepResult.Progress;
        }

        if (_broadcastOutputIndex != _broadcastOutputCount)
        {
            return await ProcessBroadcastOutputAsync(
                _broadcastOutputs[_broadcastOutputIndex],
                cancellationToken).ConfigureAwait(false);
        }

        var fetchOutput = _fetchOutputs[_fetchOutputIndex];
        if (fetchOutput.Kind == BsvTransactionFetchOutputKind.SendGetData)
        {
            var status = _session.PlanFetchEgress(fetchOutput, out var disposition);
            if (status != OperationStatus.Done || disposition != BsvPeerSessionOutputDisposition.Send)
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
            }

            AdvanceFetchOutput();
            return BsvPeerTransportStepResult.Progress;
        }

        try
        {
            await _factSink.OnFetchFactAsync(fetchOutput, CancellationToken.None).ConfigureAwait(false);
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

        AdvanceFetchOutput();
        return BsvPeerTransportStepResult.Progress;
    }

    private async ValueTask<BsvPeerTransportStepResult> ProcessBroadcastOutputAsync(
        BsvTransactionBroadcastOutput output,
        CancellationToken cancellationToken)
    {
        if (output.Kind == BsvTransactionBroadcastOutputKind.SendInventory)
        {
            var status = _session.PlanBroadcastEgress(output, out var disposition);
            if (status != OperationStatus.Done || disposition != BsvPeerSessionOutputDisposition.Send)
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.ProtocolViolation).ConfigureAwait(false);
            }

            AdvanceBroadcastOutput();
            return BsvPeerTransportStepResult.Progress;
        }

        if (output.Kind == BsvTransactionBroadcastOutputKind.SendTransaction)
        {
            IBsvTransactionPayloadSource? source;
            try
            {
                source = await _transactionSources.OpenAsync(
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

            if (source is null)
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.TransactionSourceUnavailable).ConfigureAwait(false);
            }

            _transactionSource = source;
            if (_dependencyReentryDetected)
            {
                return await TerminateForReentryAsync().ConfigureAwait(false);
            }

            Hash256 sourceTransactionId;
            try
            {
                sourceTransactionId = source.TransactionId;
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
                sourceLength = source.Length;
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

            _transactionLength = sourceLength;
            _transactionBytesRead = 0;
            _transactionPayloadEnded = false;
            if (sourceTransactionId != output.TransactionId ||
                _session.PlanTransactionEgress(output, sourceLength, sourceTransactionId) !=
                    OperationStatus.Done)
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.TransactionSourceContractViolation).ConfigureAwait(false);
            }

            AdvanceBroadcastOutput();
            return BsvPeerTransportStepResult.Progress;
        }

        try
        {
            await _factSink.OnBroadcastFactAsync(output, CancellationToken.None).ConfigureAwait(false);
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

        AdvanceBroadcastOutput();
        return BsvPeerTransportStepResult.Progress;
    }

    private async ValueTask<BsvPeerTransportStepResult> WritePendingSegmentAsync(
        MessageFrameWriteSegment pending,
        CancellationToken cancellationToken)
    {
        var bytesToWrite = Math.Min(pending.Length, _options.MaximumWriteLength);
        try
        {
            await _stream.WriteAsync(pending.Memory[..bytesToWrite], cancellationToken)
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

        if (_session.AcknowledgeEgress(pending, bytesToWrite) != OperationStatus.Done)
        {
            return await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                _transactionSource is null
                    ? BsvPeerTransportTerminalReason.ProtocolViolation
                    : BsvPeerTransportTerminalReason.TransactionHashMismatch).ConfigureAwait(false);
        }

        return BsvPeerTransportStepResult.Progress;
    }

    private async ValueTask<BsvPeerTransportStepResult> ReadTransactionChunkAsync(
        CancellationToken cancellationToken)
    {
        var source = _transactionSource!;
        var remaining = _transactionLength - _transactionBytesRead;
        if (remaining == 0)
        {
            _transactionPayloadEnded = true;
            if (_session.EndTransactionEgressPayload() != OperationStatus.Done)
            {
                return await TerminateAsync(
                    BsvPeerTransportStepKind.Faulted,
                    BsvPeerTransportTerminalReason.TransactionSourceContractViolation).ConfigureAwait(false);
            }

            return BsvPeerTransportStepResult.Progress;
        }

        var length = (int)Math.Min((ulong)_transactionBuffer.Length, remaining);
        int bytesRead;
        try
        {
            bytesRead = await source.ReadAsync(
                _transactionBuffer.AsMemory(0, length),
                cancellationToken).ConfigureAwait(false);
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

        if (bytesRead <= 0 || bytesRead > length)
        {
            return await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                BsvPeerTransportTerminalReason.TransactionSourceContractViolation).ConfigureAwait(false);
        }

        _transactionBytesRead += (ulong)bytesRead;
        if (_session.ProvideTransactionEgressChunk(
                _transactionBuffer.AsMemory(0, bytesRead)) != OperationStatus.Done)
        {
            return await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                BsvPeerTransportTerminalReason.TransactionSourceContractViolation).ConfigureAwait(false);
        }

        return BsvPeerTransportStepResult.Progress;
    }

    private async ValueTask<BsvPeerTransportStepResult> CommitEgressAsync()
    {
        var wasTransaction = _transactionSource is not null;
        var status = _session.CommitEgressCompletion();
        if (status == OperationStatus.DestinationTooSmall)
        {
            return TryStageOutputs()
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
            await ReleaseTransactionSourceAsync().ConfigureAwait(false);
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
                if (_session.HasPendingOutputs && !TryStageOutputs())
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

    private async ValueTask<BsvPeerTransportStepResult> ReadFromPeerAsync(
        CancellationToken cancellationToken)
    {
        int bytesRead;
        try
        {
            bytesRead = await _ingress.ReadAsync(cancellationToken).ConfigureAwait(false);
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
                BsvPeerTransportTerminalReason.TransportReadFailure).ConfigureAwait(false);
        }

        if (bytesRead < 0)
        {
            return await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                BsvPeerTransportTerminalReason.TransportReadFailure).ConfigureAwait(false);
        }

        if (bytesRead == 0)
        {
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

        if (!_ingress.TryCommitRead(bytesRead))
        {
            return await TerminateAsync(
                BsvPeerTransportStepKind.Faulted,
                BsvPeerTransportTerminalReason.TransportReadFailure).ConfigureAwait(false);
        }

        return BsvPeerTransportStepResult.Progress;
    }

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
        await ReleaseTransactionSourceAsync().ConfigureAwait(false);
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

    private async ValueTask ReleaseTransactionSourceAsync()
    {
        var source = _transactionSource;
        _transactionSource = null;
        _transactionLength = 0;
        _transactionBytesRead = 0;
        _transactionPayloadEnded = false;
        if (source is not null)
        {
            try
            {
                await source.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
                // Source cleanup never changes an already established transport fact.
            }
        }
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

    private bool RejectCommandReentry()
    {
        if (!_isStepping)
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
