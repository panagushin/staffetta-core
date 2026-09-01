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

        return new BsvReferenceCliApplication(
            connectorFactory(),
            runtime,
            output,
            error).RunAsync(arguments, cancellationToken);
    }
}
