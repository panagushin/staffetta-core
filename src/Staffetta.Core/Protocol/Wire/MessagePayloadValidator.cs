using System.Buffers;
using System.Security.Cryptography;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Wire;

public sealed class MessagePayloadValidator : IDisposable
{
    private readonly ulong _payloadLength;
    private readonly MessageChecksum _expectedChecksum;
    private readonly IncrementalHash? _firstHash;
    private readonly bool _requiresChecksum;

    private ulong _bytesConsumed;
    private Hash256 _payloadDoubleSha256;
    private bool _finished;
    private bool _isValid;
    private bool _hasPayloadDoubleSha256;
    private bool _disposed;

    private MessagePayloadValidator(in MessageHeader header, bool computeExtendedDoubleSha256)
    {
        _payloadLength = header.PayloadLength;
        _expectedChecksum = header.PayloadChecksum;
        _requiresChecksum = header.Format == MessageHeaderFormat.Basic;
        _firstHash = _requiresChecksum || computeExtendedDoubleSha256
            ? IncrementalHash.CreateHash(HashAlgorithmName.SHA256)
            : null;
    }

    public ulong RemainingLength => _payloadLength - _bytesConsumed;

    public bool IsCompleted => _finished;

    public static OperationStatus TryCreate(
        in MessageHeader header,
        out MessagePayloadValidator? validator) =>
        TryCreate(header, computeExtendedDoubleSha256: false, out validator);

    public static OperationStatus TryCreate(
        in MessageHeader header,
        bool computeExtendedDoubleSha256,
        out MessagePayloadValidator? validator)
    {
        validator = null;
        if (header.Format is not (MessageHeaderFormat.Basic or MessageHeaderFormat.Extended) ||
            (header.Format == MessageHeaderFormat.Extended && header.PayloadChecksum != MessageChecksum.Zero))
        {
            return OperationStatus.InvalidData;
        }

        validator = new MessagePayloadValidator(header, computeExtendedDoubleSha256);
        return OperationStatus.Done;
    }

    public OperationStatus TryGetPayloadDoubleSha256(out Hash256 payloadDoubleSha256)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        payloadDoubleSha256 = default;
        if (!_isValid || !_hasPayloadDoubleSha256)
        {
            return OperationStatus.InvalidData;
        }

        payloadDoubleSha256 = _payloadDoubleSha256;
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
            _isValid = true;
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
        if (_requiresChecksum && MessageChecksum.FromBytes(secondHash) != _expectedChecksum)
        {
            return OperationStatus.InvalidData;
        }

        _payloadDoubleSha256 = Hash256.FromWireBytes(secondHash);
        _hasPayloadDoubleSha256 = true;
        _isValid = true;
        return OperationStatus.Done;
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
