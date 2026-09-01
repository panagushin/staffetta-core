namespace Staffetta.Bsv.Cli;

internal static class Program
{
    private const string Usage =
        "Usage:\n" +
        "  staffetta-bsv handshake --peer <host:port|[IPv6]:port> [--connect-timeout-ms <n>] [--handshake-timeout-ms <n>]\n" +
        "  staffetta-bsv prepare-broadcast --tx-file <binary-path>\n" +
        "  staffetta-bsv broadcast --peer <host:port|[IPv6]:port> --tx-file <binary-path> [--connect-timeout-ms <n>] [--handshake-timeout-ms <n>] [--broadcast-timeout-ms <n>]\n" +
        "  staffetta-bsv fetch --peer <host:port|[IPv6]:port> --txid <display-hex> [--connect-timeout-ms <n>] [--handshake-timeout-ms <n>] [--fetch-timeout-ms <n>]\n" +
        "prepare-broadcast is local: it never connects or broadcasts.";

    private static async Task<int> Main(string[] args)
    {
        if (!CliArguments.TryParse(args, out var arguments, out var showHelp, out var error))
        {
            await Console.Error.WriteLineAsync(error).ConfigureAwait(false);
            await Console.Error.WriteLineAsync(Usage).ConfigureAwait(false);
            return (int)CliExitCode.Usage;
        }

        if (showHelp)
        {
            await Console.Error.WriteLineAsync(Usage).ConfigureAwait(false);
            return (int)CliExitCode.Success;
        }

        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += OnCancelKeyPress;
        try
        {
            return (int)await ReferenceCliDispatcher.RunAsync(
                arguments!,
                static () => new TcpPeerConnector(),
                SystemReferenceCliRuntime.Instance,
                Console.Out,
                Console.Error,
                cancellation.Token).ConfigureAwait(false);
        }
        finally
        {
            Console.CancelKeyPress -= OnCancelKeyPress;
        }

        void OnCancelKeyPress(object? sender, ConsoleCancelEventArgs eventArgs)
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        }
    }
}
