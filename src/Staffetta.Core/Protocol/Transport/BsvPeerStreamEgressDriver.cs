using System.Buffers;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Sessions;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Protocol.Transport;

/// <summary>
/// Owns exact stream writes and one bounded transaction payload source for a peer transport.
/// </summary>
internal sealed class BsvPeerStreamEgressDriver
{
    private readonly Stream _stream;
    private readonly IBsvTransactionPayloadSourceProvider _transactionSources;
    private readonly byte[] _transactionBuffer;
    private readonly int _maximumWriteLength;

    private IBsvTransactionPayloadSource? _transactionSource;
    private Hash256 _transactionId;
    private ulong _transactionLength;
    private ulong _transactionBytesRead;
    private bool _hasTransactionId;
    private bool _hasTransactionLength;
    private bool _transactionPayloadEnded;

    internal BsvPeerStreamEgressDriver(
        Stream stream,
        IBsvTransactionPayloadSourceProvider transactionSources,
        int transactionBufferLength,
        int maximumWriteLength)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _transactionSources = transactionSources ??
            throw new ArgumentNullException(nameof(transactionSources));
        _transactionBuffer = new byte[transactionBufferLength];
        _maximumWriteLength = maximumWriteLength;
    }

    internal bool HasTransactionSource => _transactionSource is not null;

    internal bool TransactionPayloadEnded => _transactionPayloadEnded;

    internal Hash256 TransactionId => _hasTransactionId
        ? _transactionId
        : throw new InvalidOperationException("The transaction id has not been snapshotted.");

    internal ulong TransactionLength => _hasTransactionLength
        ? _transactionLength
        : throw new InvalidOperationException("The transaction length has not been snapshotted.");

    internal async ValueTask<BsvPeerStreamPendingWrite> WritePendingPrefixAsync(
        MessageFrameWriteSegment pending,
        CancellationToken cancellationToken)
    {
        var bytesToWrite = Math.Min(pending.Length, _maximumWriteLength);
        await _stream.WriteAsync(pending.Memory[..bytesToWrite], cancellationToken)
            .ConfigureAwait(false);
        return new BsvPeerStreamPendingWrite(pending, bytesToWrite);
    }

    internal static OperationStatus AcknowledgeWrittenPrefix(
        BsvPeerSessionIngressAdapter session,
        in BsvPeerStreamPendingWrite write) =>
        session.AcknowledgeEgress(write.Segment, write.Length);

    internal async ValueTask<bool> OpenTransactionSourceAsync(
        Hash256 transactionId,
        CancellationToken cancellationToken)
    {
        if (_transactionSource is not null)
        {
            throw new InvalidOperationException("A transaction source is already active.");
        }

        _transactionSource = await _transactionSources.OpenAsync(transactionId, cancellationToken)
            .ConfigureAwait(false);
        return _transactionSource is not null;
    }

    internal Hash256 SnapshotTransactionId()
    {
        var source = GetTransactionSource();
        _transactionId = source.TransactionId;
        _hasTransactionId = true;
        return _transactionId;
    }

    internal ulong SnapshotTransactionLength()
    {
        var source = GetTransactionSource();
        _transactionLength = source.Length;
        _transactionBytesRead = 0;
        _transactionPayloadEnded = false;
        _hasTransactionLength = true;
        return _transactionLength;
    }

    internal async ValueTask<BsvPeerStreamTransactionRead> ReadTransactionChunkAsync(
        CancellationToken cancellationToken)
    {
        var source = GetTransactionSource();
        var remaining = TransactionLength - _transactionBytesRead;
        if (remaining == 0)
        {
            return BsvPeerStreamTransactionRead.EndOfPayload;
        }

        var requestedLength = (int)Math.Min((ulong)_transactionBuffer.Length, remaining);
        var bytesRead = await source.ReadAsync(
            _transactionBuffer.AsMemory(0, requestedLength),
            cancellationToken).ConfigureAwait(false);
        return new BsvPeerStreamTransactionRead(bytesRead, requestedLength);
    }

    internal OperationStatus AcceptTransactionRead(
        BsvPeerSessionIngressAdapter session,
        in BsvPeerStreamTransactionRead read)
    {
        if (read.IsEndOfPayload ||
            read.BytesRead <= 0 ||
            read.BytesRead > read.RequestedLength ||
            (ulong)read.BytesRead > TransactionLength - _transactionBytesRead)
        {
            return OperationStatus.InvalidData;
        }

        _transactionBytesRead += (ulong)read.BytesRead;
        return session.ProvideTransactionEgressChunk(
            _transactionBuffer.AsMemory(0, read.BytesRead));
    }

    internal OperationStatus EndTransactionPayload(BsvPeerSessionIngressAdapter session)
    {
        if (_transactionSource is null ||
            _transactionPayloadEnded ||
            _transactionBytesRead != TransactionLength)
        {
            return OperationStatus.InvalidData;
        }

        _transactionPayloadEnded = true;
        return session.EndTransactionEgressPayload();
    }

    internal async ValueTask<OperationStatus> CommitAsync(BsvPeerSessionIngressAdapter session)
    {
        var wasTransaction = _transactionSource is not null;
        var status = session.CommitEgressCompletion();
        if (status == OperationStatus.Done && wasTransaction)
        {
            await ReleaseTransactionSourceAsync().ConfigureAwait(false);
        }

        return status;
    }

    internal async ValueTask ReleaseTransactionSourceAsync()
    {
        var source = _transactionSource;
        ClearTransaction();
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

    private IBsvTransactionPayloadSource GetTransactionSource() =>
        _transactionSource ??
        throw new InvalidOperationException("No transaction source is active.");

    private void ClearTransaction()
    {
        _transactionSource = null;
        _transactionId = default;
        _transactionLength = 0;
        _transactionBytesRead = 0;
        _hasTransactionId = false;
        _hasTransactionLength = false;
        _transactionPayloadEnded = false;
    }
}

internal readonly record struct BsvPeerStreamPendingWrite(
    MessageFrameWriteSegment Segment,
    int Length);

internal readonly record struct BsvPeerStreamTransactionRead(
    int BytesRead,
    int RequestedLength)
{
    internal static BsvPeerStreamTransactionRead EndOfPayload => new(0, 0);

    internal bool IsEndOfPayload => RequestedLength == 0;
}
