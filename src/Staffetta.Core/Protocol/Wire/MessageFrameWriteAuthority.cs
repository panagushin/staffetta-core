using System.Buffers;

namespace Staffetta.Core.Protocol.Wire;

/// <summary>Identifies the current step of one outbound frame write.</summary>
internal enum MessageFrameWritePhase
{
    Idle,
    Header,
    AwaitingPayload,
    Payload,
    Complete,
    Aborted,
    Faulted,
    Disposed,
}

/// <summary>
/// Tracks partial transport acknowledgements for one caller-owned outbound frame without retaining
/// the complete payload.
/// </summary>
/// <remarks>
/// Instances are single-consumer and not thread-safe. The encoded header is owned by the authority.
/// Payload chunks remain owned by the caller and must stay unchanged and alive until their pending
/// segment is fully acknowledged, the frame is aborted, or the authority is disposed. A pending
/// segment remains stable only until the next successful acknowledgement or lifecycle operation.
/// </remarks>
internal sealed class MessageFrameWriteAuthority : IDisposable
{
    private readonly byte[] _headerBytes = new byte[MessageHeaderCodec.ExtendedHeaderLength];

    private ReadOnlyMemory<byte> _payloadChunk;
    private MessageFrameWritePhase _phase;
    private int _headerLength;
    private int _headerBytesAcknowledged;
    private int _payloadChunkBytesAcknowledged;
    private ulong _payloadLength;
    private ulong _payloadBytesAcknowledged;
    private ulong _revision;
    private ulong _pendingRevision;
    private bool _isDisposed;

    internal MessageFrameWritePhase Phase => _phase;

    internal bool IsComplete => _phase == MessageFrameWritePhase.Complete;

    internal bool IsFaulted => _phase == MessageFrameWritePhase.Faulted;

    internal ulong PayloadLength => _payloadLength;

    internal ulong PayloadBytesAcknowledged => _payloadBytesAcknowledged;

    internal ulong PayloadBytesRemaining => _payloadLength - _payloadBytesAcknowledged;

    /// <summary>
    /// Gets the exact header or caller-owned payload range that remains pending at the transport.
    /// </summary>
    internal MessageFrameWriteSegment PendingSegment
    {
        get
        {
            var memory = GetPendingMemory();
            return memory.IsEmpty
                ? default
                : new MessageFrameWriteSegment(this, memory, _pendingRevision);
        }
    }

    /// <summary>Encodes and starts one frame from a validated header descriptor.</summary>
    internal OperationStatus Start(
        ReadOnlySpan<byte> networkMagic,
        in MessageHeader header,
        ulong maximumPayloadLength)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (_phase == MessageFrameWritePhase.Faulted)
        {
            return OperationStatus.InvalidData;
        }

        if (_phase != MessageFrameWritePhase.Idle)
        {
            return Fault();
        }

        _headerBytes.AsSpan().Clear();
        var status = MessageHeaderCodec.TryWrite(
            _headerBytes,
            networkMagic,
            header,
            maximumPayloadLength,
            out var headerLength);
        if (status != OperationStatus.Done)
        {
            _headerBytes.AsSpan().Clear();
            return status;
        }

        _headerLength = headerLength;
        _payloadLength = header.PayloadLength;
        _phase = MessageFrameWritePhase.Header;
        if (!TryIssueLease())
        {
            return OperationStatus.InvalidData;
        }

        return OperationStatus.Done;
    }

    /// <summary>
    /// Supplies the next non-empty caller-owned payload range after the header is acknowledged.
    /// </summary>
    internal OperationStatus ProvidePayloadChunk(ReadOnlyMemory<byte> chunk)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (_phase == MessageFrameWritePhase.Faulted)
        {
            return OperationStatus.InvalidData;
        }

        if (_phase != MessageFrameWritePhase.AwaitingPayload ||
            chunk.IsEmpty ||
            (ulong)chunk.Length > PayloadBytesRemaining)
        {
            return Fault();
        }

        _payloadChunk = chunk;
        _payloadChunkBytesAcknowledged = 0;
        _phase = MessageFrameWritePhase.Payload;
        if (!TryIssueLease())
        {
            return OperationStatus.InvalidData;
        }

        return OperationStatus.Done;
    }

    /// <summary>Acknowledges a positive prefix of the currently pending exact byte segment.</summary>
    internal OperationStatus Acknowledge(
        in MessageFrameWriteSegment segment,
        int bytesWritten)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (_phase == MessageFrameWritePhase.Faulted)
        {
            return OperationStatus.InvalidData;
        }

        var pendingMemory = GetPendingMemory();
        if (bytesWritten <= 0 ||
            !segment.Matches(this, pendingMemory, _pendingRevision))
        {
            return Fault();
        }

        switch (_phase)
        {
            case MessageFrameWritePhase.Header:
                if (bytesWritten > _headerLength - _headerBytesAcknowledged)
                {
                    return Fault();
                }

                _headerBytesAcknowledged += bytesWritten;
                if (_headerBytesAcknowledged == _headerLength)
                {
                    InvalidateLease();
                    _phase = _payloadLength == 0
                        ? MessageFrameWritePhase.Complete
                        : MessageFrameWritePhase.AwaitingPayload;
                }
                else if (!TryIssueLease())
                {
                    return OperationStatus.InvalidData;
                }

                return OperationStatus.Done;

            case MessageFrameWritePhase.Payload:
                if (bytesWritten > _payloadChunk.Length - _payloadChunkBytesAcknowledged)
                {
                    return Fault();
                }

                _payloadChunkBytesAcknowledged += bytesWritten;
                _payloadBytesAcknowledged += (ulong)bytesWritten;
                if (_payloadChunkBytesAcknowledged == _payloadChunk.Length)
                {
                    _payloadChunk = ReadOnlyMemory<byte>.Empty;
                    _payloadChunkBytesAcknowledged = 0;
                    InvalidateLease();
                    _phase = _payloadBytesAcknowledged == _payloadLength
                        ? MessageFrameWritePhase.Complete
                        : MessageFrameWritePhase.AwaitingPayload;
                }
                else if (!TryIssueLease())
                {
                    return OperationStatus.InvalidData;
                }

                return OperationStatus.Done;

            default:
                return Fault();
        }
    }

    /// <summary>Stops an active frame and releases its caller-owned payload chunk reference.</summary>
    internal OperationStatus Abort()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (_phase == MessageFrameWritePhase.Faulted)
        {
            return OperationStatus.InvalidData;
        }

        if (_phase is not MessageFrameWritePhase.Header and
            not MessageFrameWritePhase.AwaitingPayload and
            not MessageFrameWritePhase.Payload)
        {
            return Fault();
        }

        ClearFrame();
        _phase = MessageFrameWritePhase.Aborted;
        return OperationStatus.Done;
    }

    /// <summary>Returns a completed or aborted authority to idle for the next explicit start.</summary>
    internal OperationStatus Reset()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (_phase == MessageFrameWritePhase.Faulted)
        {
            return OperationStatus.InvalidData;
        }

        if (_phase is not MessageFrameWritePhase.Complete and
            not MessageFrameWritePhase.Aborted)
        {
            return Fault();
        }

        ClearFrame();
        _phase = MessageFrameWritePhase.Idle;
        return OperationStatus.Done;
    }

    public void Dispose()
    {
        if (_isDisposed)
        {
            return;
        }

        ClearFrame();
        _phase = MessageFrameWritePhase.Disposed;
        _isDisposed = true;
    }

    private OperationStatus Fault()
    {
        ClearFrame();
        _phase = MessageFrameWritePhase.Faulted;
        return OperationStatus.InvalidData;
    }

    private ReadOnlyMemory<byte> GetPendingMemory() => _phase switch
    {
        MessageFrameWritePhase.Header =>
            _headerBytes.AsMemory(
                _headerBytesAcknowledged,
                _headerLength - _headerBytesAcknowledged),
        MessageFrameWritePhase.Payload =>
            _payloadChunk[_payloadChunkBytesAcknowledged..],
        _ => ReadOnlyMemory<byte>.Empty,
    };

    private bool TryIssueLease()
    {
        if (_revision == ulong.MaxValue)
        {
            _ = Fault();
            return false;
        }

        _revision++;
        _pendingRevision = _revision;
        return true;
    }

    private void InvalidateLease()
    {
        if (_revision != ulong.MaxValue)
        {
            _revision++;
        }

        _pendingRevision = 0;
    }

    private void ClearFrame()
    {
        InvalidateLease();
        _headerBytes.AsSpan().Clear();
        _payloadChunk = ReadOnlyMemory<byte>.Empty;
        _headerLength = 0;
        _headerBytesAcknowledged = 0;
        _payloadChunkBytesAcknowledged = 0;
        _payloadLength = 0;
        _payloadBytesAcknowledged = 0;
    }
}

internal readonly struct MessageFrameWriteSegment
{
    private readonly MessageFrameWriteAuthority? _authority;
    private readonly ulong _revision;

    internal MessageFrameWriteSegment(
        MessageFrameWriteAuthority authority,
        ReadOnlyMemory<byte> memory,
        ulong revision)
    {
        _authority = authority;
        Memory = memory;
        _revision = revision;
    }

    internal ReadOnlyMemory<byte> Memory { get; }

    internal ReadOnlySpan<byte> Span => Memory.Span;

    internal int Length => Memory.Length;

    internal bool IsEmpty => Memory.IsEmpty;

    internal bool Matches(
        MessageFrameWriteAuthority authority,
        ReadOnlyMemory<byte> pendingMemory,
        ulong pendingRevision) =>
        ReferenceEquals(_authority, authority) &&
        _revision != 0 &&
        _revision == pendingRevision &&
        Memory.Equals(pendingMemory);
}
