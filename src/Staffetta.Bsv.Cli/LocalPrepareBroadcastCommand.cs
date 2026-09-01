namespace Staffetta.Bsv.Cli;

internal sealed class LocalPrepareBroadcastCommand
{
    private readonly NdjsonEventWriter _events;
    private readonly TextWriter _error;

    internal LocalPrepareBroadcastCommand(TextWriter output, TextWriter error)
    {
        _events = new NdjsonEventWriter(output);
        _error = error;
    }

    internal async ValueTask<CliExitCode> RunAsync(
        string path,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, cancellationToken)
                .ConfigureAwait(false);
            await _events.WriteBroadcastPreparedAsync(prepared.Summary, CancellationToken.None)
                .ConfigureAwait(false);
            return CliExitCode.Success;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return CliExitCode.Canceled;
        }
        catch (TransactionInputException exception)
        {
            await WriteDiagnosticAsync(exception.Message).ConfigureAwait(false);
            return CliExitCode.TransactionInput;
        }
        catch (Exception exception)
        {
            await WriteDiagnosticAsync($"Output or internal failure: {exception.GetType().Name}.")
                .ConfigureAwait(false);
            return CliExitCode.InternalError;
        }
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
