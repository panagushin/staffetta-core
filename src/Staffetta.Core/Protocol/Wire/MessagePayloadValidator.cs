using System.Buffers;
using System.Security.Cryptography;

namespace Staffetta.Core.Protocol.Wire;

public sealed class MessagePayloadValidator : IDisposable
{
    private readonly ulong _payloadLength;
    private readonly MessageChecksum _expectedChecksum;
    private readonly IncrementalHash? _firstHash;

    private ulong _bytesConsumed;
    private bool _finished;
    private bool _disposed;

    private MessagePayloadValidator(in MessageHeader header)
    {
        _payloadLength = header.PayloadLength;
        _expectedChecksum = header.PayloadChecksum;
        _firstHash = header.Format == MessageHeaderFormat.Basic
            ? IncrementalHash.CreateHash(HashAlgorithmName.SHA256)
            : null;
    }

    public ulong RemainingLength => _payloadLength - _bytesConsumed;

    public bool IsCompleted => _finished;

    public static OperationStatus TryCreate(
        in MessageHeader header,
        out MessagePayloadValidator? validator)
    {
        validator = null;
        if (header.Format is not (MessageHeaderFormat.Basic or MessageHeaderFormat.Extended) ||
            (header.Format == MessageHeaderFormat.Extended && header.PayloadChecksum != MessageChecksum.Zero))
        {
            return OperationStatus.InvalidData;
        }

        validator = new MessagePayloadValidator(header);
        return OperationStatus.Done;
    }

    public OperationStatus Consume(ReadOnlySpan<byte> source, out int bytesConsumed)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        bytesConsumed = 0;
        if (_finished)
        {
            return OperationStatus.InvalidData;
        }

        var acceptedLength = (int)Math.Min((ulong)source.Length, RemainingLength);
        if (acceptedLength > 0)
        {
            _firstHash?.AppendData(source[..acceptedLength]);
            _bytesConsumed += (ulong)acceptedLength;
            bytesConsumed = acceptedLength;
        }

        if (RemainingLength > 0)
        {
            return OperationStatus.NeedMoreData;
        }

        _finished = true;
        if (_firstHash is null)
        {
            return OperationStatus.Done;
        }

        Span<byte> firstHash = stackalloc byte[SHA256.HashSizeInBytes];
        if (!_firstHash.TryGetHashAndReset(firstHash, out var firstHashLength) ||
            firstHashLength != SHA256.HashSizeInBytes)
        {
            return OperationStatus.InvalidData;
        }

        Span<byte> secondHash = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(firstHash, secondHash);
        var actualChecksum = MessageChecksum.FromBytes(secondHash);
        return actualChecksum == _expectedChecksum
            ? OperationStatus.Done
            : OperationStatus.InvalidData;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _firstHash?.Dispose();
        _disposed = true;
    }
}
