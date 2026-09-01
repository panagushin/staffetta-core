using System.Net.Sockets;
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
                await _events.WriteSessionStoppedAsync(CancellationToken.None).ConfigureAwait(false);
                return CliExitCode.Success;
            }

            if (completed == run)
            {
                timeoutCancellation.Cancel();
                var actorCompletion = await run.ConfigureAwait(false);
                connection.Abort();
                await connection.DisposeAsync().ConfigureAwait(false);
                connection = null;
                return await ReportActorTerminalAsync(bridge, actorCompletion).ConfigureAwait(false);
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
        BsvPeerTransportActorCompletion completion)
    {
        if (completion.Kind == BsvPeerTransportActorCompletionKind.Stopped)
        {
            await _events.WriteSessionTerminalAsync(
                    "handshake",
                    "stopped",
                    "transport_stopped",
                    cancellationToken: CancellationToken.None)
                .ConfigureAwait(false);
            return CliExitCode.PeerSessionFailure;
        }

        var result = completion.TransportResult;
        await _events.WriteSessionTerminalAsync(
                "handshake",
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
