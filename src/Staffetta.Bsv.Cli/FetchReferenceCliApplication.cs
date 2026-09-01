using System.Buffers;
using System.Net.Sockets;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Transport;

namespace Staffetta.Bsv.Cli;

internal sealed class FetchReferenceCliApplication
{
    private readonly IPeerConnector _connector;
    private readonly IReferenceCliRuntime _runtime;
    private readonly NdjsonEventWriter _events;
    private readonly TextWriter _error;

    internal FetchReferenceCliApplication(
        IPeerConnector connector,
        IReferenceCliRuntime runtime,
        TextWriter output,
        TextWriter error)
    {
        _connector = connector ?? throw new ArgumentNullException(nameof(connector));
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _events = new NdjsonEventWriter(output);
        _error = error ?? throw new ArgumentNullException(nameof(error));
    }

    internal async ValueTask<CliExitCode> RunAsync(
        CliArguments arguments,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Command != ReferenceCliCommand.Fetch || arguments.TransactionId is not Hash256 transactionId)
        {
            throw new ArgumentException("The fetch path requires one typed transaction id.", nameof(arguments));
        }

        IPeerConnection? connection = null;
        CorePeerFetchSessionBridge? bridge = null;
        try
        {
            var connect = await ConnectAsync(arguments, cancellationToken).ConfigureAwait(false);
            if (connect.ExitCode is not null)
            {
                await WriteConnectTerminalAsync(
                        arguments.Peer!.Value.Display,
                        transactionId,
                        connect.ExitCode.Value)
                    .ConfigureAwait(false);
                return connect.ExitCode.Value;
            }

            connection = connect.Connection!;
            await _events.WriteConnectionOpenedAsync(
                    arguments.Peer!.Value.Display,
                    connection.RemoteDisplay,
                    CancellationToken.None)
                .ConfigureAwait(false);
            bridge = new CorePeerFetchSessionBridge(
                connection.Stream,
                connection.RemoteAddress,
                connection.RemotePort,
                connection.RemoteDisplay,
                transactionId,
                _events,
                _runtime.GetUnixTimeSeconds(),
                _runtime.CreateNonce());

            var submission = bridge.QueueFetch();
            await _events.WriteFetchQueueAsync(
                    connection.RemoteDisplay,
                    transactionId,
                    submission.Status,
                    CancellationToken.None)
                .ConfigureAwait(false);
            if (submission.Status != BsvPeerTransportCommandQueueStatus.Accepted || submission.Application is null)
            {
                return CliExitCode.InternalError;
            }

            var run = bridge.RunAsync();
            var handshakeResult = await AwaitHandshakeAsync(
                    arguments,
                    bridge,
                    connection,
                    run,
                    cancellationToken)
                .ConfigureAwait(false);
            if (handshakeResult is not null)
            {
                connection = null;
                return handshakeResult.Value;
            }

            using var fetchCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var fetchTimeout = _runtime.DelayAsync(arguments.FetchTimeout, fetchCancellation.Token);
            var applicationReport = bridge.ReportApplicationAsync(submission.Application);
            var applicationCompleted = await Task.WhenAny(applicationReport, run, fetchTimeout)
                .ConfigureAwait(false);
            if (applicationCompleted != applicationReport)
            {
                var result = await FinishBeforeApplicationAsync(
                        bridge,
                        connection,
                        run,
                        applicationReport,
                        fetchTimeout,
                        transactionId,
                        cancellationToken)
                    .ConfigureAwait(false);
                connection = null;
                return result;
            }

            var application = await applicationReport.ConfigureAwait(false);
            if (application.Kind != BsvPeerTransportCommandApplicationKind.PumpApplied ||
                application.Status != OperationStatus.Done)
            {
                await StopAndAbortAsync(bridge, connection).ConfigureAwait(false);
                await connection.DisposeAsync().ConfigureAwait(false);
                connection = null;
                await _events.WriteFetchTerminalAsync(
                        bridge.Peer,
                        transactionId,
                        "rejected",
                        $"command_{application.Kind}_{application.Status}",
                        cancellationToken: CancellationToken.None)
                    .ConfigureAwait(false);
                return CliExitCode.PeerSessionFailure;
            }

            var completed = await Task.WhenAny(
                    bridge.Received,
                    bridge.ReceivedBeforeRequest,
                    bridge.NotFound,
                    bridge.MonetaryInvalid,
                    run,
                    fetchTimeout)
                .ConfigureAwait(false);
            fetchCancellation.Cancel();
            if (completed == run)
            {
                var actorCompletion = await run.ConfigureAwait(false);
                connection.Abort();
                await connection.DisposeAsync().ConfigureAwait(false);
                connection = null;
                return await ReportFetchActorTerminalAsync(bridge, transactionId, actorCompletion)
                    .ConfigureAwait(false);
            }

            if (completed == fetchTimeout && !cancellationToken.IsCancellationRequested)
            {
                await fetchTimeout.ConfigureAwait(false);
            }

            await StopAndAbortAsync(bridge, connection).ConfigureAwait(false);
            await connection.DisposeAsync().ConfigureAwait(false);
            connection = null;

            var committedOutcome = await AdjudicateCommittedOutcomeAsync(bridge, transactionId, run)
                .ConfigureAwait(false);
            if (committedOutcome is not null)
            {
                return committedOutcome.Value;
            }

            var canceled = cancellationToken.IsCancellationRequested;
            await _events.WriteFetchTerminalAsync(
                    bridge.Peer,
                    transactionId,
                    canceled ? "canceled" : "timeout",
                    canceled ? "operator_canceled" : "deadline_exceeded",
                    cancellationToken: CancellationToken.None)
                .ConfigureAwait(false);
            return canceled ? CliExitCode.Canceled : CliExitCode.Timeout;
        }
        catch (Exception exception)
        {
            if (connection is not null && bridge is not null)
            {
                try { await StopAndAbortAsync(bridge, connection).ConfigureAwait(false); }
                catch { }
            }
            else if (connection is not null)
            {
                connection.Abort();
            }

            await WriteDiagnosticAsync($"Fetch session or output failure: {exception.GetType().Name}.")
                .ConfigureAwait(false);
            return CliExitCode.InternalError;
        }
        finally
        {
            if (bridge is not null)
            {
                try { await bridge.DisposeAsync().ConfigureAwait(false); }
                catch { }
            }

            if (connection is not null)
            {
                try { await connection.DisposeAsync().ConfigureAwait(false); }
                catch { }
            }
        }
    }

    private async ValueTask<CliExitCode?> AwaitHandshakeAsync(
        CliArguments arguments,
        CorePeerFetchSessionBridge bridge,
        IPeerConnection connection,
        Task<BsvPeerTransportActorCompletion> run,
        CancellationToken cancellationToken)
    {
        using var timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var timeout = _runtime.DelayAsync(arguments.HandshakeTimeout, timeoutCancellation.Token);
        var completed = await Task.WhenAny(bridge.Ready, run, timeout).ConfigureAwait(false);
        if (bridge.Ready.IsCompletedSuccessfully)
        {
            timeoutCancellation.Cancel();
            return null;
        }

        if (completed == run)
        {
            timeoutCancellation.Cancel();
            var actorCompletion = await run.ConfigureAwait(false);
            connection.Abort();
            await connection.DisposeAsync().ConfigureAwait(false);
            return await ReportHandshakeActorTerminalAsync(bridge, actorCompletion).ConfigureAwait(false);
        }

        var canceled = cancellationToken.IsCancellationRequested;
        if (!canceled)
        {
            await timeout.ConfigureAwait(false);
        }

        await StopAndAbortAsync(bridge, connection).ConfigureAwait(false);
        await connection.DisposeAsync().ConfigureAwait(false);
        await _events.WriteFetchTerminalAsync(
                bridge.Peer,
                bridge.TargetTransactionId,
                canceled ? "canceled" : "timeout",
                canceled ? "operator_canceled_during_handshake" : "handshake_deadline_exceeded",
                cancellationToken: CancellationToken.None)
            .ConfigureAwait(false);
        return canceled ? CliExitCode.Canceled : CliExitCode.Timeout;
    }

    private async ValueTask<CliExitCode> FinishBeforeApplicationAsync(
        CorePeerFetchSessionBridge bridge,
        IPeerConnection connection,
        Task<BsvPeerTransportActorCompletion> run,
        Task<BsvPeerTransportCommandApplication> applicationReport,
        Task timeout,
        Hash256 transactionId,
        CancellationToken cancellationToken)
    {
        if (run.IsCompleted)
        {
            var completion = await run.ConfigureAwait(false);
            _ = await applicationReport.ConfigureAwait(false);
            connection.Abort();
            await connection.DisposeAsync().ConfigureAwait(false);
            return await ReportFetchActorTerminalAsync(bridge, transactionId, completion).ConfigureAwait(false);
        }

        var canceled = cancellationToken.IsCancellationRequested;
        if (!canceled)
        {
            await timeout.ConfigureAwait(false);
        }

        await StopAndAbortAsync(bridge, connection).ConfigureAwait(false);
        _ = await applicationReport.ConfigureAwait(false);
        await connection.DisposeAsync().ConfigureAwait(false);
        var committedOutcome = await AdjudicateCommittedOutcomeAsync(bridge, transactionId, run)
            .ConfigureAwait(false);
        if (committedOutcome is not null)
        {
            return committedOutcome.Value;
        }

        await _events.WriteFetchTerminalAsync(
                bridge.Peer,
                transactionId,
                canceled ? "canceled" : "timeout",
                canceled ? "operator_canceled_before_application" : "deadline_exceeded_before_application",
                cancellationToken: CancellationToken.None)
            .ConfigureAwait(false);
        return canceled ? CliExitCode.Canceled : CliExitCode.Timeout;
    }

    private async ValueTask<CliExitCode?> AdjudicateCommittedOutcomeAsync(
        CorePeerFetchSessionBridge bridge,
        Hash256 transactionId,
        Task<BsvPeerTransportActorCompletion> run)
    {
        if (bridge.Received.IsCompletedSuccessfully)
        {
            await _events.WriteFetchTerminalAsync(
                    bridge.Peer,
                    transactionId,
                    "received",
                    "validated_transaction_received",
                    cancellationToken: CancellationToken.None)
                .ConfigureAwait(false);
            await _events.WriteSessionStoppedAsync("fetch_received", CancellationToken.None)
                .ConfigureAwait(false);
            return CliExitCode.Success;
        }

        if (bridge.ReceivedBeforeRequest.IsCompletedSuccessfully)
        {
            await _events.WriteFetchTerminalAsync(
                    bridge.Peer,
                    transactionId,
                    "unexpected",
                    "received_before_request_commit",
                    cancellationToken: CancellationToken.None)
                .ConfigureAwait(false);
            return CliExitCode.PeerSessionFailure;
        }

        if (bridge.NotFound.IsCompletedSuccessfully)
        {
            await _events.WriteFetchTerminalAsync(
                    bridge.Peer,
                    transactionId,
                    "not_found",
                    "peer_notfound",
                    cancellationToken: CancellationToken.None)
                .ConfigureAwait(false);
            return CliExitCode.PeerSessionFailure;
        }

        if (bridge.MonetaryInvalid.IsCompletedSuccessfully)
        {
            await _events.WriteFetchTerminalAsync(
                    bridge.Peer,
                    transactionId,
                    "invalid",
                    "monetary_invalid",
                    cancellationToken: CancellationToken.None)
                .ConfigureAwait(false);
            return CliExitCode.PeerSessionFailure;
        }

        if (run.IsCompletedSuccessfully)
        {
            var actorCompletion = await run.ConfigureAwait(false);
            if (IsInternalActorFailure(actorCompletion))
            {
                return await ReportFetchActorTerminalAsync(bridge, transactionId, actorCompletion)
                    .ConfigureAwait(false);
            }
        }

        return null;
    }

    private async ValueTask<CliExitCode> ReportHandshakeActorTerminalAsync(
        CorePeerFetchSessionBridge bridge,
        BsvPeerTransportActorCompletion completion)
    {
        var kind = completion.Kind == BsvPeerTransportActorCompletionKind.TransportTerminal
            ? completion.TransportResult.Kind.ToString()
            : "stopped";
        var reason = completion.Kind == BsvPeerTransportActorCompletionKind.TransportTerminal
            ? completion.TransportResult.Reason.ToString()
            : "transport_stopped";
        await _events.WriteFetchTerminalAsync(
                bridge.Peer,
                bridge.TargetTransactionId,
                IsInternalActorFailure(completion) ? "internal_failure" : "handshake_terminal",
                bridge.HandshakeTerminalReason != default
                    ? bridge.HandshakeTerminalReason.ToString()
                    : reason,
                kind,
                reason,
                CancellationToken.None)
            .ConfigureAwait(false);
        return IsInternalActorFailure(completion) ? CliExitCode.InternalError : CliExitCode.PeerSessionFailure;
    }

    private async ValueTask<CliExitCode> ReportFetchActorTerminalAsync(
        CorePeerFetchSessionBridge bridge,
        Hash256 transactionId,
        BsvPeerTransportActorCompletion completion)
    {
        var transportKind = completion.Kind.ToString();
        var transportReason = completion.Kind == BsvPeerTransportActorCompletionKind.TransportTerminal
            ? $"{completion.TransportResult.Kind}:{completion.TransportResult.Reason}"
            : "Stopped";
        await _events.WriteFetchTerminalAsync(
                bridge.Peer,
                transactionId,
                IsInternalActorFailure(completion) ? "internal_failure" : "transport_terminal",
                completion.Kind == BsvPeerTransportActorCompletionKind.TransportTerminal
                    ? completion.TransportResult.Reason.ToString()
                    : "transport_stopped",
                transportKind,
                transportReason,
                CancellationToken.None)
            .ConfigureAwait(false);
        return IsInternalActorFailure(completion) ? CliExitCode.InternalError : CliExitCode.PeerSessionFailure;
    }

    private async ValueTask<(IPeerConnection? Connection, CliExitCode? ExitCode)> ConnectAsync(
        CliArguments arguments,
        CancellationToken cancellationToken)
    {
        using var connectCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var connect = _connector.ConnectAsync(arguments.Peer!.Value, connectCancellation.Token).AsTask();
        var timeout = _runtime.DelayAsync(arguments.ConnectTimeout, timeoutCancellation.Token);
        var completed = await Task.WhenAny(connect, timeout).ConfigureAwait(false);
        if (completed == connect)
        {
            try
            {
                var connection = await connect.ConfigureAwait(false);
                var canceled = cancellationToken.IsCancellationRequested;
                if (!canceled && timeout.IsFaulted)
                {
                    connection.Abort();
                    await connection.DisposeAsync().ConfigureAwait(false);
                    await timeout.ConfigureAwait(false);
                }

                var timedOut = timeout.IsCompletedSuccessfully;
                timeoutCancellation.Cancel();
                if (canceled || timedOut)
                {
                    connection.Abort();
                    await connection.DisposeAsync().ConfigureAwait(false);
                    return (null, canceled ? CliExitCode.Canceled : CliExitCode.Timeout);
                }

                return (connection, null);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return (null, CliExitCode.Canceled);
            }
            catch (Exception exception) when (exception is SocketException or IOException)
            {
                await WriteDiagnosticAsync("Connection failed.").ConfigureAwait(false);
                return (null, CliExitCode.ConnectionFailure);
            }
        }

        var operatorCanceled = cancellationToken.IsCancellationRequested;
        if (!operatorCanceled)
        {
            try
            {
                await timeout.ConfigureAwait(false);
            }
            catch
            {
                connectCancellation.Cancel();
                _ = DisposeLateConnectionAsync(connect);
                throw;
            }
        }

        connectCancellation.Cancel();
        _ = DisposeLateConnectionAsync(connect);
        return (null, operatorCanceled ? CliExitCode.Canceled : CliExitCode.Timeout);
    }

    private static async Task DisposeLateConnectionAsync(Task<IPeerConnection> connectionTask)
    {
        try
        {
            var connection = await connectionTask.ConfigureAwait(false);
            connection.Abort();
            await connection.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception)
        {
        }
    }

    private static async ValueTask StopAndAbortAsync(
        CorePeerFetchSessionBridge bridge,
        IPeerConnection connection)
    {
        var stop = bridge.StopAsync().AsTask();
        connection.Abort();
        await stop.ConfigureAwait(false);
    }

    private static bool IsInternalActorFailure(BsvPeerTransportActorCompletion completion) =>
        completion.Kind == BsvPeerTransportActorCompletionKind.TransportTerminal &&
        completion.TransportResult.Reason is BsvPeerTransportTerminalReason.FactSinkFailure or
            BsvPeerTransportTerminalReason.DependencyReentry;

    private async ValueTask WriteConnectTerminalAsync(
        string peer,
        Hash256 transactionId,
        CliExitCode exitCode)
    {
        await _events.WriteFetchTerminalAsync(
                peer,
                transactionId,
                exitCode == CliExitCode.Canceled ? "canceled" :
                    exitCode == CliExitCode.Timeout ? "timeout" : "connection_failed",
                exitCode == CliExitCode.Canceled ? "operator_canceled" :
                    exitCode == CliExitCode.Timeout ? "deadline_exceeded" : "connection_failed",
                cancellationToken: CancellationToken.None)
            .ConfigureAwait(false);
    }

    private async ValueTask WriteDiagnosticAsync(string message)
    {
        try
        {
            await _error.WriteLineAsync(message.AsMemory(), CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception)
        {
        }
    }
}
