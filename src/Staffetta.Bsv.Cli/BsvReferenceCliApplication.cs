using System.Net.Sockets;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Transport;

namespace Staffetta.Bsv.Cli;

internal sealed class BsvReferenceCliApplication
{
    private readonly IPeerConnector _connector;
    private readonly IReferenceCliRuntime _runtime;
    private readonly NdjsonEventWriter _events;
    private readonly TextWriter _error;

    internal BsvReferenceCliApplication(
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
        if (arguments.Command != ReferenceCliCommand.Handshake)
        {
            throw new ArgumentException("The peer application accepts only the handshake command.", nameof(arguments));
        }

        return await RunHandshakeAsync(arguments, cancellationToken).ConfigureAwait(false);
    }

    internal async ValueTask<CliExitCode> RunBroadcastAsync(
        CliArguments arguments,
        PreparedBinaryTransaction prepared,
        CancellationToken cancellationToken) =>
        await RunBroadcastCoreAsync(arguments, prepared.Summary, prepared, cancellationToken)
            .ConfigureAwait(false);

    internal async ValueTask<CliExitCode> RunBroadcastAsync(
        CliArguments arguments,
        LegacyTransactionSummary summary,
        IBsvTransactionPayloadSourceProvider transactionSources,
        CancellationToken cancellationToken) =>
        await RunBroadcastCoreAsync(arguments, summary, transactionSources, cancellationToken)
            .ConfigureAwait(false);

    private async ValueTask<CliExitCode> RunBroadcastCoreAsync(
        CliArguments arguments,
        LegacyTransactionSummary summary,
        IBsvTransactionPayloadSourceProvider transactionSources,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(transactionSources);
        if (arguments.Command != ReferenceCliCommand.Broadcast)
        {
            throw new ArgumentException("The broadcast path accepts only the broadcast command.", nameof(arguments));
        }

        IPeerConnection? connection = null;
        CorePeerSessionBridge? bridge = null;
        try
        {
            await _events.WriteBroadcastPreparedAsync(
                    summary,
                    willBroadcast: true,
                    cancellationToken: CancellationToken.None)
                .ConfigureAwait(false);
            var connect = await ConnectAsync(arguments, cancellationToken).ConfigureAwait(false);
            if (connect.ExitCode is not null)
            {
                await WriteConnectTerminalAsync(connect.ExitCode.Value).ConfigureAwait(false);
                return connect.ExitCode.Value;
            }

            connection = connect.Connection!;
            await _events.WriteConnectionOpenedAsync(
                    arguments.Peer!.Value.Display,
                    connection.RemoteDisplay,
                    CancellationToken.None)
                .ConfigureAwait(false);
            bridge = new CorePeerSessionBridge(
                connection.Stream,
                connection.RemoteAddress,
                connection.RemotePort,
                connection.RemoteDisplay,
                _events,
                _runtime.GetUnixTimeSeconds(),
                _runtime.CreateNonce(),
                transactionSources);
            var submission = bridge.QueueBroadcast(summary.TransactionId);
            await _events.WriteBroadcastQueueAsync(summary.TransactionId, submission.Status, CancellationToken.None)
                .ConfigureAwait(false);
            if (submission.Status != BsvPeerTransportCommandQueueStatus.Accepted || submission.Application is null)
            {
                return CliExitCode.InternalError;
            }

            var run = bridge.RunAsync();
            using var handshakeCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var handshakeTimeout = _runtime.DelayAsync(arguments.HandshakeTimeout, handshakeCancellation.Token);
            var handshakeCompleted = await Task.WhenAny(bridge.Ready, run, handshakeTimeout).ConfigureAwait(false);
            if (!bridge.Ready.IsCompletedSuccessfully)
            {
                if (handshakeCompleted == run)
                {
                    handshakeCancellation.Cancel();
                    var actorCompletion = await run.ConfigureAwait(false);
                    connection.Abort();
                    await connection.DisposeAsync().ConfigureAwait(false);
                    connection = null;
                    return await ReportActorTerminalAsync(bridge, actorCompletion, "handshake").ConfigureAwait(false);
                }

                var canceled = cancellationToken.IsCancellationRequested;
                if (!canceled)
                {
                    await handshakeTimeout.ConfigureAwait(false);
                }

                await StopAndAbortAsync(bridge, connection).ConfigureAwait(false);
                await connection.DisposeAsync().ConfigureAwait(false);
                connection = null;
                await _events.WriteSessionTerminalAsync(
                        "handshake",
                        canceled ? "canceled" : "timeout",
                        canceled ? "operator_canceled" : "deadline_exceeded",
                        cancellationToken: CancellationToken.None)
                    .ConfigureAwait(false);
                return canceled ? CliExitCode.Canceled : CliExitCode.Timeout;
            }

            handshakeCancellation.Cancel();
            using var broadcastCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var broadcastTimeout = _runtime.DelayAsync(arguments.BroadcastTimeout, broadcastCancellation.Token);
            var applicationReport = bridge.ReportBroadcastApplicationAsync(
                    summary.TransactionId,
                    submission.Application);
            var applicationCompleted = await Task.WhenAny(applicationReport, run, broadcastTimeout)
                .ConfigureAwait(false);
            if (applicationCompleted != applicationReport)
            {
                if (applicationCompleted == run)
                {
                    broadcastCancellation.Cancel();
                    var actorCompletion = await run.ConfigureAwait(false);
                    _ = await applicationReport.ConfigureAwait(false);
                    connection.Abort();
                    await connection.DisposeAsync().ConfigureAwait(false);
                    connection = null;
                    return await ReportActorTerminalAsync(bridge, actorCompletion, "broadcast").ConfigureAwait(false);
                }

                var applicationCanceled = cancellationToken.IsCancellationRequested;
                if (!applicationCanceled)
                {
                    await broadcastTimeout.ConfigureAwait(false);
                }

                await StopAndAbortAsync(bridge, connection).ConfigureAwait(false);
                _ = await applicationReport.ConfigureAwait(false);
                await connection.DisposeAsync().ConfigureAwait(false);
                connection = null;
                if (run.IsCompletedSuccessfully && IsInternalActorFailure(await run.ConfigureAwait(false)))
                {
                    return await ReportActorTerminalAsync(bridge, await run.ConfigureAwait(false), "broadcast")
                        .ConfigureAwait(false);
                }

                if (bridge.Rejected.IsCompletedSuccessfully)
                {
                    await _events.WriteSessionTerminalAsync(
                            "broadcast",
                            "rejected",
                            "peer_reject",
                            cancellationToken: CancellationToken.None)
                        .ConfigureAwait(false);
                    return CliExitCode.PeerSessionFailure;
                }

                await _events.WriteSessionTerminalAsync(
                        "broadcast",
                        applicationCanceled ? "canceled" : "timeout",
                        applicationCanceled ? "operator_canceled_before_application" : "deadline_exceeded_before_application",
                        cancellationToken: CancellationToken.None)
                    .ConfigureAwait(false);
                return applicationCanceled ? CliExitCode.Canceled : CliExitCode.Timeout;
            }

            var application = await applicationReport.ConfigureAwait(false);
            if (application.Kind != BsvPeerTransportCommandApplicationKind.PumpApplied ||
                application.Status != System.Buffers.OperationStatus.Done)
            {
                await StopAndAbortAsync(bridge, connection).ConfigureAwait(false);
                await connection.DisposeAsync().ConfigureAwait(false);
                connection = null;
                await _events.WriteSessionTerminalAsync(
                        "broadcast",
                        "rejected",
                        $"command_{application.Kind}_{application.Status}",
                        cancellationToken: CancellationToken.None)
                    .ConfigureAwait(false);
                return CliExitCode.PeerSessionFailure;
            }

            var broadcastCompleted = await Task.WhenAny(bridge.DeliveryOutcome, run, broadcastTimeout)
                .ConfigureAwait(false);
            if (broadcastCompleted == bridge.DeliveryOutcome)
            {
                broadcastCancellation.Cancel();
                var outcome = await bridge.DeliveryOutcome.ConfigureAwait(false);
                if (outcome == Staffetta.Core.Protocol.Relay.BsvTransactionBroadcastOutputKind.Rejected)
                {
                    await StopAndAbortAsync(bridge, connection).ConfigureAwait(false);
                    await connection.DisposeAsync().ConfigureAwait(false);
                    connection = null;
                    await _events.WriteSessionTerminalAsync(
                            "broadcast",
                            "rejected",
                            "peer_reject",
                            cancellationToken: CancellationToken.None)
                        .ConfigureAwait(false);
                    return CliExitCode.PeerSessionFailure;
                }

                var result = await ObserveAfterSentAsync(
                        bridge,
                        connection,
                        run,
                        summary.TransactionId,
                        cancellationToken)
                    .ConfigureAwait(false);
                connection = null;
                return result;
            }

            if (broadcastCompleted == run)
            {
                broadcastCancellation.Cancel();
                var actorCompletion = await run.ConfigureAwait(false);
                connection.Abort();
                await connection.DisposeAsync().ConfigureAwait(false);
                connection = null;
                return await ReportActorTerminalAsync(bridge, actorCompletion, "broadcast").ConfigureAwait(false);
            }

            var broadcastCanceled = cancellationToken.IsCancellationRequested;
            if (!broadcastCanceled)
            {
                await broadcastTimeout.ConfigureAwait(false);
            }

            await StopAndAbortAsync(bridge, connection).ConfigureAwait(false);
            await connection.DisposeAsync().ConfigureAwait(false);
            connection = null;
            if (run.IsCompletedSuccessfully && IsInternalActorFailure(await run.ConfigureAwait(false)))
            {
                return await ReportActorTerminalAsync(bridge, await run.ConfigureAwait(false), "broadcast")
                    .ConfigureAwait(false);
            }

            if (bridge.Rejected.IsCompletedSuccessfully)
            {
                await _events.WriteSessionTerminalAsync(
                        "broadcast",
                        "rejected",
                        "peer_reject",
                        cancellationToken: CancellationToken.None)
                    .ConfigureAwait(false);
                return CliExitCode.PeerSessionFailure;
            }

            if (bridge.DeliveryOutcome.IsCompletedSuccessfully &&
                await bridge.DeliveryOutcome.ConfigureAwait(false) ==
                    Staffetta.Core.Protocol.Relay.BsvTransactionBroadcastOutputKind.SentToPeer)
            {
                var observed = bridge.ObservedFromPeer.IsCompletedSuccessfully;
                await _events.WriteBroadcastObservationAsync(
                        summary.TransactionId,
                        observed ? "observed" : "not_observed",
                        observed ? "relay_back" :
                            broadcastCanceled ? "operator_canceled_after_send" : "deadline_raced_with_send",
                        cancellationToken: CancellationToken.None)
                    .ConfigureAwait(false);
                await _events.WriteSessionStoppedAsync(
                        observed ? "sent_and_observed" :
                            broadcastCanceled ? "sent_observation_canceled" : "sent_not_observed",
                        CancellationToken.None)
                    .ConfigureAwait(false);
                return CliExitCode.Success;
            }

            await _events.WriteSessionTerminalAsync(
                    "broadcast",
                    broadcastCanceled ? "canceled" : "timeout",
                    broadcastCanceled ? "operator_canceled" : "deadline_exceeded",
                    cancellationToken: CancellationToken.None)
                .ConfigureAwait(false);
            return broadcastCanceled ? CliExitCode.Canceled : CliExitCode.Timeout;
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

            await WriteDiagnosticAsync($"Session or output failure: {exception.GetType().Name}.")
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

    private async ValueTask<CliExitCode> ObserveAfterSentAsync(
        CorePeerSessionBridge bridge,
        IPeerConnection connection,
        Task<BsvPeerTransportActorCompletion> run,
        Staffetta.Core.Protocol.Cryptography.Hash256 transactionId,
        CancellationToken cancellationToken)
    {
        using var observationCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var window = _runtime.DelayAsync(TimeSpan.FromSeconds(2), observationCancellation.Token);
        var completed = await Task.WhenAny(bridge.Rejected, bridge.ObservedFromPeer, run, window)
            .ConfigureAwait(false);
        if (bridge.Rejected.IsCompletedSuccessfully)
        {
            observationCancellation.Cancel();
            await StopAndAbortAsync(bridge, connection).ConfigureAwait(false);
            await connection.DisposeAsync().ConfigureAwait(false);
            await _events.WriteSessionTerminalAsync(
                    "broadcast",
                    "rejected",
                    "peer_reject",
                    cancellationToken: CancellationToken.None)
                .ConfigureAwait(false);
            return CliExitCode.PeerSessionFailure;
        }

        string observationReason;
        string stopReason;
        string? transportKind = null;
        string? transportReason = null;
        BsvPeerTransportActorCompletion? observedActorCompletion = null;
        if (bridge.ObservedFromPeer.IsCompletedSuccessfully)
        {
            observationCancellation.Cancel();
            observationReason = "relay_back";
            stopReason = "sent_and_observed";
        }
        else if (completed == run)
        {
            observationCancellation.Cancel();
            var actorCompletion = await run.ConfigureAwait(false);
            observedActorCompletion = actorCompletion;
            if (IsInternalActorFailure(actorCompletion))
            {
                connection.Abort();
                await connection.DisposeAsync().ConfigureAwait(false);
                return await ReportActorTerminalAsync(bridge, actorCompletion, "broadcast")
                    .ConfigureAwait(false);
            }

            transportKind = actorCompletion.Kind.ToString();
            transportReason = actorCompletion.Kind == BsvPeerTransportActorCompletionKind.TransportTerminal
                ? $"{actorCompletion.TransportResult.Kind}:{actorCompletion.TransportResult.Reason}"
                : null;
            observationReason = "transport_terminal_after_send";
            stopReason = "sent_transport_terminal";
        }
        else if (cancellationToken.IsCancellationRequested)
        {
            observationReason = "operator_canceled_after_send";
            stopReason = "sent_observation_canceled";
        }
        else
        {
            await window.ConfigureAwait(false);
            observationReason = "window_elapsed";
            stopReason = "sent_not_observed";
        }

        await StopAndAbortAsync(bridge, connection).ConfigureAwait(false);
        await connection.DisposeAsync().ConfigureAwait(false);
        if (observedActorCompletion is null && run.IsCompletedSuccessfully)
        {
            var actorCompletion = await run.ConfigureAwait(false);
            if (IsInternalActorFailure(actorCompletion))
            {
                return await ReportActorTerminalAsync(bridge, actorCompletion, "broadcast")
                    .ConfigureAwait(false);
            }
        }

        if (bridge.Rejected.IsCompletedSuccessfully)
        {
            await _events.WriteSessionTerminalAsync(
                    "broadcast",
                    "rejected",
                    "peer_reject",
                    cancellationToken: CancellationToken.None)
                .ConfigureAwait(false);
            return CliExitCode.PeerSessionFailure;
        }

        if (bridge.ObservedFromPeer.IsCompletedSuccessfully)
        {
            observationReason = "relay_back";
            stopReason = "sent_and_observed";
        }

        await _events.WriteBroadcastObservationAsync(
                transactionId,
                bridge.ObservedFromPeer.IsCompletedSuccessfully ? "observed" : "not_observed",
                observationReason,
                transportKind,
                transportReason,
                CancellationToken.None)
            .ConfigureAwait(false);
        await _events.WriteSessionStoppedAsync(stopReason, CancellationToken.None).ConfigureAwait(false);
        return CliExitCode.Success;
    }

    private static bool IsInternalActorFailure(BsvPeerTransportActorCompletion completion) =>
        completion.Kind == BsvPeerTransportActorCompletionKind.TransportTerminal &&
        completion.TransportResult.Reason is BsvPeerTransportTerminalReason.FactSinkFailure or
            BsvPeerTransportTerminalReason.DependencyReentry;

    private async ValueTask<CliExitCode> RunHandshakeAsync(
        CliArguments arguments,
        CancellationToken cancellationToken)
    {
        IPeerConnection? connection = null;
        CorePeerSessionBridge? bridge = null;
        try
        {
            var connect = await ConnectAsync(arguments, cancellationToken).ConfigureAwait(false);
            if (connect.ExitCode is not null)
            {
                try
                {
                    await _events.WriteSessionTerminalAsync(
                            "connect",
                            connect.ExitCode == CliExitCode.Canceled ? "canceled" :
                                connect.ExitCode == CliExitCode.Timeout ? "timeout" : "faulted",
                            connect.ExitCode == CliExitCode.Canceled ? "operator_canceled" :
                                connect.ExitCode == CliExitCode.Timeout ? "deadline_exceeded" : "connection_failed",
                            cancellationToken: CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    await WriteDiagnosticAsync($"Output failure: {exception.GetType().Name}.").ConfigureAwait(false);
                    return CliExitCode.InternalError;
                }

                return connect.ExitCode.Value;
            }

            connection = connect.Connection!;
            var requestedPeer = arguments.Peer!.Value.Display;
            try
            {
                await _events.WriteConnectionOpenedAsync(
                        requestedPeer,
                        connection.RemoteDisplay,
                        CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                await WriteDiagnosticAsync($"Output failure: {exception.GetType().Name}.").ConfigureAwait(false);
                return CliExitCode.InternalError;
            }

            bridge = new CorePeerSessionBridge(
                connection.Stream,
                connection.RemoteAddress,
                connection.RemotePort,
                connection.RemoteDisplay,
                _events,
                _runtime.GetUnixTimeSeconds(),
                _runtime.CreateNonce());
            var run = bridge.RunAsync();
            using var timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var timeout = _runtime.DelayAsync(arguments.HandshakeTimeout, timeoutCancellation.Token);
            var completed = await Task.WhenAny(bridge.Ready, run, timeout).ConfigureAwait(false);

            if (bridge.Ready.IsCompletedSuccessfully)
            {
                timeoutCancellation.Cancel();
                await StopAndAbortAsync(bridge, connection).ConfigureAwait(false);
                await connection.DisposeAsync().ConfigureAwait(false);
                connection = null;
                await _events.WriteSessionStoppedAsync(cancellationToken: CancellationToken.None)
                    .ConfigureAwait(false);
                return CliExitCode.Success;
            }

            if (completed == run)
            {
                timeoutCancellation.Cancel();
                var actorCompletion = await run.ConfigureAwait(false);
                connection.Abort();
                await connection.DisposeAsync().ConfigureAwait(false);
                connection = null;
                return await ReportActorTerminalAsync(bridge, actorCompletion, "handshake").ConfigureAwait(false);
            }

            var canceled = cancellationToken.IsCancellationRequested;
            if (!canceled)
            {
                await timeout.ConfigureAwait(false);
            }

            await StopAndAbortAsync(bridge, connection).ConfigureAwait(false);
            await connection.DisposeAsync().ConfigureAwait(false);
            connection = null;
            await _events.WriteSessionTerminalAsync(
                    "handshake",
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

            await WriteDiagnosticAsync($"Session or output failure: {exception.GetType().Name}.")
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
                var connectCanceled = cancellationToken.IsCancellationRequested;
                if (!connectCanceled && timeout.IsFaulted)
                {
                    connection.Abort();
                    await connection.DisposeAsync().ConfigureAwait(false);
                    await timeout.ConfigureAwait(false);
                }

                var timedOut = timeout.IsCompletedSuccessfully;
                timeoutCancellation.Cancel();
                if (connectCanceled || timedOut)
                {
                    connection.Abort();
                    await connection.DisposeAsync().ConfigureAwait(false);
                    return (null, connectCanceled ? CliExitCode.Canceled : CliExitCode.Timeout);
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

        var canceled = cancellationToken.IsCancellationRequested;
        if (!canceled)
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
        return (null, canceled ? CliExitCode.Canceled : CliExitCode.Timeout);
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
        CorePeerSessionBridge bridge,
        IPeerConnection connection)
    {
        var stop = bridge.StopAsync().AsTask();
        connection.Abort();
        await stop.ConfigureAwait(false);
    }

    private async ValueTask<CliExitCode> ReportActorTerminalAsync(
        CorePeerSessionBridge bridge,
        BsvPeerTransportActorCompletion completion,
        string stage)
    {
        if (completion.Kind == BsvPeerTransportActorCompletionKind.Stopped)
        {
            await _events.WriteSessionTerminalAsync(
                    stage,
                    "stopped",
                    "transport_stopped",
                    cancellationToken: CancellationToken.None)
                .ConfigureAwait(false);
            return CliExitCode.PeerSessionFailure;
        }

        var result = completion.TransportResult;
        await _events.WriteSessionTerminalAsync(
                stage,
                result.Kind.ToString(),
                result.Reason.ToString(),
                bridge.HandshakeTerminalReason,
                CancellationToken.None)
            .ConfigureAwait(false);
        return result.Reason is BsvPeerTransportTerminalReason.FactSinkFailure or
            BsvPeerTransportTerminalReason.DependencyReentry
            ? CliExitCode.InternalError
            : CliExitCode.PeerSessionFailure;
    }

    private async ValueTask WriteConnectTerminalAsync(CliExitCode exitCode)
    {
        await _events.WriteSessionTerminalAsync(
                "connect",
                exitCode == CliExitCode.Canceled ? "canceled" :
                    exitCode == CliExitCode.Timeout ? "timeout" : "faulted",
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
