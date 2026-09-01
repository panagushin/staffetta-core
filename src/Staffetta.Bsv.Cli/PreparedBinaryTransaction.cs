using System.Buffers;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Transport;

namespace Staffetta.Bsv.Cli;

internal sealed class TransactionInputException : Exception
{
    internal TransactionInputException(string message)
        : base(message)
    {
    }

    internal TransactionInputException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

internal sealed class PreparedBinaryTransaction :
    IBsvTransactionPayloadSourceProvider,
    IBsvTransactionPayloadSource,
    IAsyncDisposable
{
    internal const int BufferLength = 64 * 1024;

    private readonly FileStream _stream;
    private bool _leaseIssued;
    private bool _disposed;

    private PreparedBinaryTransaction(FileStream stream, LegacyTransactionSummary summary)
    {
        _stream = stream;
        Summary = summary;
    }

    internal LegacyTransactionSummary Summary { get; }

    public Hash256 TransactionId => Summary.TransactionId;

    public ulong Length => Summary.SerializedLength;

    internal int MaximumReadRequestLength { get; private set; }

    internal static async ValueTask<PreparedBinaryTransaction> OpenAndValidateAsync(
        string path,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        FileStream stream;
        try
        {
            stream = new FileStream(path, new FileStreamOptions
            {
                Access = FileAccess.Read,
                BufferSize = 1,
                Mode = FileMode.Open,
                Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
                Share = FileShare.Read,
            });
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new TransactionInputException("The transaction file could not be opened.", exception);
        }

        try
        {
            var length = stream.Length;
            if (length <= 0)
            {
                throw new TransactionInputException("The transaction file is empty.");
            }

            var buffer = ArrayPool<byte>.Shared.Rent(BufferLength);
            try
            {
                using var parser = new LegacyTransactionParser(NoOpTransactionSink.Instance);
                ulong accepted = 0;
                while (accepted < (ulong)length)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var requested = (int)Math.Min((ulong)BufferLength, (ulong)length - accepted);
                    var read = await stream.ReadAsync(buffer.AsMemory(0, requested), cancellationToken)
                        .ConfigureAwait(false);
                    if (read == 0)
                    {
                        throw new TransactionInputException("The transaction file ended before its snapshotted length.");
                    }

                    var status = parser.Consume(buffer.AsSpan(0, read), out var consumed);
                    accepted = checked(accepted + (ulong)consumed);
                    if (status == OperationStatus.InvalidData)
                    {
                        throw new TransactionInputException("The file is not a canonical legacy transaction.");
                    }

                    if (consumed != read || (status == OperationStatus.Done && accepted != (ulong)length))
                    {
                        throw new TransactionInputException("The transaction file contains trailing bytes.");
                    }
                }

                if (!parser.IsReadyToCommit ||
                    parser.Commit(out var summary) != OperationStatus.Done ||
                    summary.SerializedLength != (ulong)length ||
                    stream.Length != length)
                {
                    throw new TransactionInputException("The transaction file is incomplete or changed during validation.");
                }

                stream.Position = 0;
                return new PreparedBinaryTransaction(stream, summary);
            }
            finally
            {
                buffer.AsSpan(0, BufferLength).Clear();
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        catch (OperationCanceledException)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        catch (TransactionInputException)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw new TransactionInputException("The transaction file could not be read consistently.", exception);
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public ValueTask<IBsvTransactionPayloadSource?> OpenAsync(
        Hash256 transactionId,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        if (_leaseIssued || transactionId != TransactionId)
        {
            return ValueTask.FromResult<IBsvTransactionPayloadSource?>(null);
        }

        _leaseIssued = true;
        _stream.Position = 0;
        return ValueTask.FromResult<IBsvTransactionPayloadSource?>(this);
    }

    public ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        MaximumReadRequestLength = Math.Max(MaximumReadRequestLength, destination.Length);
        return _stream.ReadAsync(destination, cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        await _stream.DisposeAsync().ConfigureAwait(false);
    }

    private sealed class NoOpTransactionSink : ILegacyTransactionSink
    {
        internal static NoOpTransactionSink Instance { get; } = new();

        public void OnTransactionStarted(int version, ulong inputCount) { }

        public void OnInputStarted(ulong inputIndex, in OutPoint previousOutput, ulong scriptLength) { }

        public void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script) { }

        public void OnInputCompleted(ulong inputIndex, uint sequence) { }

        public void OnOutputsStarted(ulong outputCount) { }

        public void OnOutputStarted(ulong outputIndex, long valueSatoshis, ulong scriptLength) { }

        public void OnOutputScriptChunk(ulong outputIndex, ReadOnlySpan<byte> script) { }

        public void OnOutputCompleted(ulong outputIndex) { }

        public void OnTransactionCommitted(in LegacyTransactionSummary summary) { }

        public void OnTransactionAborted() { }
    }
}
