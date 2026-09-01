namespace Staffetta.Bsv.Cli;

internal static class ReferenceCliDispatcher
{
    internal static ValueTask<CliExitCode> RunAsync(
        CliArguments arguments,
        Func<IPeerConnector> connectorFactory,
        IReferenceCliRuntime runtime,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(connectorFactory);
        if (arguments.Command == ReferenceCliCommand.PrepareBroadcast)
        {
            return new LocalPrepareBroadcastCommand(output, error)
                .RunAsync(arguments.TransactionFile!, cancellationToken);
        }

        if (arguments.Command == ReferenceCliCommand.Broadcast)
        {
            return RunBroadcastAsync(
                arguments,
                connectorFactory,
                runtime,
                output,
                error,
                cancellationToken);
        }

        if (arguments.Command == ReferenceCliCommand.Fetch)
        {
            return new FetchReferenceCliApplication(
                connectorFactory(),
                runtime,
                output,
                error).RunAsync(arguments, cancellationToken);
        }

        return new BsvReferenceCliApplication(
            connectorFactory(),
            runtime,
            output,
            error).RunAsync(arguments, cancellationToken);
    }

    private static async ValueTask<CliExitCode> RunBroadcastAsync(
        CliArguments arguments,
        Func<IPeerConnector> connectorFactory,
        IReferenceCliRuntime runtime,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        PreparedBinaryTransaction? prepared = null;
        try
        {
            prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(
                    arguments.TransactionFile!,
                    cancellationToken)
                .ConfigureAwait(false);
            return await new BsvReferenceCliApplication(connectorFactory(), runtime, output, error)
                .RunBroadcastAsync(arguments, prepared, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return CliExitCode.Canceled;
        }
        catch (TransactionInputException exception)
        {
            try { await error.WriteLineAsync(exception.Message).ConfigureAwait(false); }
            catch { }
            return CliExitCode.TransactionInput;
        }
        finally
        {
            if (prepared is not null)
            {
                await prepared.DisposeAsync().ConfigureAwait(false);
            }
        }
    }
}
