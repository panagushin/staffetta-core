using System.Buffers;
using Staffetta.Core.Protocol.Sessions;

namespace Staffetta.Core.Protocol.Transport;

internal readonly struct BsvPeerStreamReadOperation
{
    private readonly BsvPeerStreamIngressDriver _owner;

    internal BsvPeerStreamReadOperation(
        BsvPeerStreamIngressDriver owner,
        long revision,
        Task<int> completion)
    {
        _owner = owner;
        Revision = revision;
        Completion = completion;
    }

    internal long Revision { get; }

    internal Task<int> Completion { get; }

    internal bool IsCompleted => Completion.IsCompleted;

    internal bool IsCanceled => Completion.IsCanceled;

    internal bool IsOwnedBy(BsvPeerStreamIngressDriver owner) =>
        ReferenceEquals(_owner, owner);
}

internal sealed class BsvPeerStreamIngressDriver
{
    private readonly Stream _stream;
    private readonly BsvPeerSessionIngressAdapter _session;
    private readonly byte[] _readBuffer;

    private int _readOffset;
    private int _readCount;
    private bool _isFramePartial;
    private Task<int>? _pendingRead;
    private long _pendingReadRevision;
    private long _nextReadRevision;

    internal BsvPeerStreamIngressDriver(
        Stream stream,
        BsvPeerSessionIngressAdapter session,
        int readBufferLength)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _session = session ?? throw new ArgumentNullException(nameof(session));
        _readBuffer = new byte[readBufferLength];
    }

    internal bool HasBufferedInput => _readOffset != _readCount;

    internal bool IsFramePartial => _isFramePartial;

    internal bool HasPendingRead => _pendingRead is not null;

    internal OperationStatus ConsumeBufferedInput(out int bytesConsumed) =>
        _session.Consume(
            _readBuffer.AsSpan(_readOffset, _readCount - _readOffset),
            out bytesConsumed);

    internal bool TryCommitConsume(OperationStatus status, int bytesConsumed)
    {
        if (bytesConsumed < 0 || bytesConsumed > _readCount - _readOffset)
        {
            return false;
        }

        _readOffset += bytesConsumed;
        if (status == OperationStatus.NeedMoreData)
        {
            _isFramePartial = true;
        }
        else if (status == OperationStatus.Done ||
            (status == OperationStatus.DestinationTooSmall && bytesConsumed != 0))
        {
            _isFramePartial = false;
        }

        if (_readOffset == _readCount)
        {
            _readOffset = 0;
            _readCount = 0;
        }

        return true;
    }

    internal BsvPeerStreamReadOperation BeginRead(CancellationToken cancellationToken)
    {
        if (_pendingRead is not null || HasBufferedInput)
        {
            throw new InvalidOperationException("Only one peer read may be pending.");
        }

        var revision = checked(_nextReadRevision + 1);
        _nextReadRevision = revision;
        _pendingReadRevision = revision;
        try
        {
            _pendingRead = _stream.ReadAsync(_readBuffer, cancellationToken).AsTask();
        }
        catch (Exception exception)
        {
            _pendingRead = Task.FromException<int>(exception);
        }

        return new BsvPeerStreamReadOperation(this, _pendingReadRevision, _pendingRead);
    }

    internal bool IsPendingRead(in BsvPeerStreamReadOperation read) =>
        read.IsOwnedBy(this) &&
        read.Revision == _pendingReadRevision &&
        ReferenceEquals(_pendingRead, read.Completion);

    internal bool TryAbandonRead(in BsvPeerStreamReadOperation read)
    {
        if (!IsPendingRead(read))
        {
            return false;
        }

        _pendingRead = null;
        _pendingReadRevision = 0;
        return true;
    }

    internal bool TryCommitRead(in BsvPeerStreamReadOperation read, int bytesRead)
    {
        if (!IsPendingRead(read) ||
            bytesRead <= 0 ||
            bytesRead > _readBuffer.Length ||
            HasBufferedInput)
        {
            return false;
        }

        _pendingRead = null;
        _pendingReadRevision = 0;
        _readOffset = 0;
        _readCount = bytesRead;
        return true;
    }

    internal OperationStatus CompleteEndOfInput() => _session.CompleteEndOfInput();
}
