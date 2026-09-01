using System.Buffers;
using Staffetta.Core.Protocol.Sessions;

namespace Staffetta.Core.Protocol.Transport;

internal sealed class BsvPeerStreamIngressDriver
{
    private readonly Stream _stream;
    private readonly BsvPeerSessionIngressAdapter _session;
    private readonly byte[] _readBuffer;

    private int _readOffset;
    private int _readCount;
    private bool _isFramePartial;

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

    internal ValueTask<int> ReadAsync(CancellationToken cancellationToken) =>
        _stream.ReadAsync(_readBuffer, cancellationToken);

    internal bool TryCommitRead(int bytesRead)
    {
        if (bytesRead <= 0 || bytesRead > _readBuffer.Length || HasBufferedInput)
        {
            return false;
        }

        _readOffset = 0;
        _readCount = bytesRead;
        return true;
    }

    internal OperationStatus CompleteEndOfInput() => _session.CompleteEndOfInput();
}
