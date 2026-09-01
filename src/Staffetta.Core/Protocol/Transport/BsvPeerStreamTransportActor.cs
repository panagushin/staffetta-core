using System.Buffers;
using System.Threading.Channels;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Transactions;

namespace Staffetta.Core.Protocol.Transport;

internal enum BsvPeerTransportCommandKind
{
    Broadcast,
    Fetch,
}

internal enum BsvPeerTransportCommandQueueStatus
{
    Accepted,
    QueueFull,
    Stopped,
}

internal enum BsvPeerTransportCommandApplicationKind
{
    PumpApplied,
    Rejected,
    Stopped,
    Terminal,
}

internal readonly record struct BsvPeerTransportCommandApplication(
    BsvPeerTransportCommandApplicationKind Kind,
    OperationStatus Status);

internal readonly record struct BsvPeerTransportCommandSubmission(
    BsvPeerTransportCommandQueueStatus Status,
    Task<BsvPeerTransportCommandApplication>? Application);

internal enum BsvPeerTransportActorCompletionKind
{
    Stopped,
    TransportTerminal,
}

internal readonly record struct BsvPeerTransportActorCompletion(
    BsvPeerTransportActorCompletionKind Kind,
    BsvPeerTransportStepResult TransportResult)
{
    internal static BsvPeerTransportActorCompletion Stopped =>
        new(BsvPeerTransportActorCompletionKind.Stopped, default);

    internal static BsvPeerTransportActorCompletion Terminal(
        BsvPeerTransportStepResult result) =>
        new(BsvPeerTransportActorCompletionKind.TransportTerminal, result);
}

internal sealed class BsvPeerStreamTransportActor : IAsyncDisposable
{
    internal const int CommandCapacity = 8;

    private static readonly AsyncLocal<BsvPeerStreamTransportActor?> ExecutingActor = new();

    private readonly BsvPeerStreamTransportPump _pump;
    private readonly Channel<Command> _commands;
    private readonly CancellationTokenSource _readCancellation = new();
    private readonly object _lifecycleGate = new();
    private readonly TaskCompletionSource _stopSignal =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task<BsvPeerTransportActorCompletion>? _runTask;
    private Task? _stopTask;
    private int _runStarted;
    private int _stopRequested;
    private int _admissionClosed;

    internal BsvPeerStreamTransportActor(
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
        _pump = new BsvPeerStreamTransportPump(
            stream,
            expectedNetworkMagic,
            maximumInboundPayloadLength,
            minimumPeerProtocolVersion,
            localHandshake,
            transactionSink,
            transactionSources,
            factSink,
            options);
        _commands = Channel.CreateBounded<Command>(new BoundedChannelOptions(CommandCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false,
        });
    }

    internal BsvPeerTransportCommandSubmission QueueBroadcast(Hash256 transactionId) =>
        Queue(BsvPeerTransportCommandKind.Broadcast, transactionId);

    internal BsvPeerTransportCommandSubmission QueueFetch(Hash256 transactionId) =>
        Queue(BsvPeerTransportCommandKind.Fetch, transactionId);

    internal Task<BsvPeerTransportActorCompletion> RunAsync()
    {
        lock (_lifecycleGate)
        {
            if (_stopRequested != 0)
            {
                throw new InvalidOperationException("A stopped peer actor cannot be run.");
            }

            if (_runStarted != 0)
            {
                throw new InvalidOperationException("The peer actor may only run once.");
            }

            _runStarted = 1;
            var completion = new TaskCompletionSource<BsvPeerTransportActorCompletion>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            _runTask = completion.Task;
            _ = RunAndCompleteAsync(completion);
            return _runTask;
        }
    }

    private async Task RunAndCompleteAsync(
        TaskCompletionSource<BsvPeerTransportActorCompletion> completion)
    {
        try
        {
            var result = await RunCoreAsync().ConfigureAwait(false);
            completion.TrySetResult(result);
        }
        catch (Exception exception)
        {
            completion.TrySetException(exception);
        }
    }

    internal ValueTask StopAsync()
    {
        var calledFromActor = ReferenceEquals(ExecutingActor.Value, this);
        lock (_lifecycleGate)
        {
            if (_stopTask is not null)
            {
                return calledFromActor ? ValueTask.CompletedTask : new ValueTask(_stopTask);
            }

            if (_stopRequested == 0)
            {
                _stopRequested = 1;
                CloseAdmission();
                _stopSignal.TrySetResult();
                _commands.Writer.TryComplete();
                _readCancellation.Cancel();
            }

            _stopTask = StopCoreAsync(_runTask);
            return calledFromActor ? ValueTask.CompletedTask : new ValueTask(_stopTask);
        }
    }

    private async Task StopCoreAsync(Task<BsvPeerTransportActorCompletion>? run)
    {
        try
        {
            if (run is not null)
            {
                await run.ConfigureAwait(false);
            }
            else
            {
                CompleteQueued(BsvPeerTransportCommandApplicationKind.Stopped);
                await _pump.DisposeAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            _readCancellation.Dispose();
        }
    }

    public ValueTask DisposeAsync() => StopAsync();

    private BsvPeerTransportCommandSubmission Queue(
        BsvPeerTransportCommandKind kind,
        Hash256 transactionId)
    {
        if (Volatile.Read(ref _admissionClosed) != 0)
        {
            return new BsvPeerTransportCommandSubmission(
                BsvPeerTransportCommandQueueStatus.Stopped,
                null);
        }

        var command = new Command(kind, transactionId);
        if (_commands.Writer.TryWrite(command))
        {
            return new BsvPeerTransportCommandSubmission(
                BsvPeerTransportCommandQueueStatus.Accepted,
                command.Application.Task);
        }

        return new BsvPeerTransportCommandSubmission(
            Volatile.Read(ref _admissionClosed) != 0
                ? BsvPeerTransportCommandQueueStatus.Stopped
                : BsvPeerTransportCommandQueueStatus.QueueFull,
            null);
    }

    private async Task<BsvPeerTransportActorCompletion> RunCoreAsync()
    {
        var previousActor = ExecutingActor.Value;
        ExecutingActor.Value = this;
        BsvPeerStreamReadOperation? read = null;
        try
        {
            if (_pump.StartHandshake() != OperationStatus.Done)
            {
                return BsvPeerTransportActorCompletion.Terminal(
                    new BsvPeerTransportStepResult(
                        BsvPeerTransportStepKind.Faulted,
                        BsvPeerTransportTerminalReason.ProtocolViolation));
            }

            while (true)
            {
                if (read is { IsCompleted: true } completedRead &&
                    !(Volatile.Read(ref _stopRequested) != 0 && completedRead.IsCanceled))
                {
                    var result = await _pump.ApplyPeerReadAsync(completedRead, _readCancellation.Token)
                        .ConfigureAwait(false);
                    read = null;
                    if (result.Kind != BsvPeerTransportStepKind.Progress)
                    {
                        return CompleteTerminal(result);
                    }

                    continue;
                }

                if (Volatile.Read(ref _stopRequested) != 0)
                {
                    CompleteQueued(BsvPeerTransportCommandApplicationKind.Stopped);
                    while (await _pump.TryDrainCommittedFactAsync().ConfigureAwait(false))
                    {
                    }

                    if (_pump.IsTerminal)
                    {
                        return CompleteTerminal(_pump.TerminalResult);
                    }

                    _readCancellation.Cancel();
                    if (read is not null)
                    {
                        var result = await _pump.ApplyPeerReadAsync(
                            read.Value,
                            _readCancellation.Token)
                            .ConfigureAwait(false);
                        read = null;
                        if (result.Kind != BsvPeerTransportStepKind.Progress &&
                            !IsRequestedCancellation(result))
                        {
                            return BsvPeerTransportActorCompletion.Terminal(result);
                        }
                    }

                    return BsvPeerTransportActorCompletion.Stopped;
                }

                if (_pump.HasLocalWork)
                {
                    var local = await _pump.StepLocalAsync(_readCancellation.Token).ConfigureAwait(false);
                    if (local.Kind == BsvPeerTransportDriveKind.Terminal)
                    {
                        return CompleteTerminal(local.StepResult);
                    }

                    continue;
                }

                if (read is null)
                {
                    read = _pump.BeginPeerRead(_readCancellation.Token);
                    continue;
                }

                if (_pump.CanApplyActorCommand && _commands.Reader.TryRead(out var command))
                {
                    var status = command.Kind == BsvPeerTransportCommandKind.Broadcast
                        ? _pump.StartBroadcast(command.TransactionId)
                        : _pump.StartFetch(command.TransactionId);
                    command.Application.TrySetResult(new BsvPeerTransportCommandApplication(
                        status == OperationStatus.Done
                            ? BsvPeerTransportCommandApplicationKind.PumpApplied
                            : BsvPeerTransportCommandApplicationKind.Rejected,
                        status));
                    continue;
                }

                if (!_pump.CanApplyActorCommand)
                {
                    await Task.WhenAny(read.Value.Completion, _stopSignal.Task).ConfigureAwait(false);
                    continue;
                }

                var commandAvailable = _commands.Reader.WaitToReadAsync().AsTask();
                await Task.WhenAny(
                    read.Value.Completion,
                    commandAvailable,
                    _stopSignal.Task).ConfigureAwait(false);
            }
        }
        finally
        {
            try
            {
                CloseAdmission();
                _commands.Writer.TryComplete();
                CompleteQueued(
                    Volatile.Read(ref _stopRequested) != 0
                        ? BsvPeerTransportCommandApplicationKind.Stopped
                        : BsvPeerTransportCommandApplicationKind.Terminal);
                _readCancellation.Cancel();
                await _pump.DisposeAsync().ConfigureAwait(false);
            }
            finally
            {
                ExecutingActor.Value = previousActor;
            }
        }
    }

    private void CompleteQueued(BsvPeerTransportCommandApplicationKind kind)
    {
        while (_commands.Reader.TryRead(out var command))
        {
            command.Application.TrySetResult(
                new BsvPeerTransportCommandApplication(kind, OperationStatus.InvalidData));
        }
    }

    private void CloseAdmission() => Interlocked.Exchange(ref _admissionClosed, 1);

    private BsvPeerTransportActorCompletion CompleteTerminal(
        BsvPeerTransportStepResult result) =>
        IsRequestedCancellation(result)
            ? BsvPeerTransportActorCompletion.Stopped
            : BsvPeerTransportActorCompletion.Terminal(result);

    private bool IsRequestedCancellation(BsvPeerTransportStepResult result) =>
        Volatile.Read(ref _stopRequested) != 0 &&
        result.Kind == BsvPeerTransportStepKind.Canceled &&
        result.Reason == BsvPeerTransportTerminalReason.Canceled;

    private sealed class Command
    {
        internal Command(BsvPeerTransportCommandKind kind, Hash256 transactionId)
        {
            Kind = kind;
            TransactionId = transactionId;
            Application = new TaskCompletionSource<BsvPeerTransportCommandApplication>(
                TaskCreationOptions.RunContinuationsAsynchronously);
        }

        internal BsvPeerTransportCommandKind Kind { get; }

        internal Hash256 TransactionId { get; }

        internal TaskCompletionSource<BsvPeerTransportCommandApplication> Application { get; }
    }
}
