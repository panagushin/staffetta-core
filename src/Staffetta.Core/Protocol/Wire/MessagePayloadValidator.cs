using System.Buffers;
using System.Security.Cryptography;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Wire;

/// <summary>Incrementally checks one declared payload length and, for basic messages, its checksum without retaining payload bytes.</summary>
/// <remarks>Instances are single-consumer and not thread-safe. Extended hashing is optional and has no peer-supplied digest to compare. Completion validates framing only, not payload structure or business meaning.</remarks>
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

    /// <summary>Gets the unconsumed portion of the declared payload length.</summary>
    public ulong RemainingLength => _payloadLength - _bytesConsumed;

    /// <summary>Gets whether the declared length was consumed and final validation attempted, whether successful or not.</summary>
    public bool IsCompleted => _finished;

    /// <summary>Creates a validator that hashes basic payloads and only counts extended payload bytes.</summary>
    /// <param name="header">A header whose format and extended checksum will be checked; other header fields must already be validated.</param>
    /// <param name="validator">A new caller-disposed validator on success; otherwise null.</param>
    /// <returns>Done, or InvalidData for an unknown format or nonzero extended checksum.</returns>
    public static OperationStatus TryCreate(
        in MessageHeader header,
        out MessagePayloadValidator? validator) =>
        TryCreate(header, computeExtendedDoubleSha256: false, out validator);

    /// <summary>Creates a validator with optional full-digest computation for extended payloads.</summary>
    /// <param name="header">A header whose format and extended checksum will be checked; other header fields must already be validated.</param>
    /// <param name="computeExtendedDoubleSha256">Whether to hash extended payloads; basic payloads are always hashed.</param>
    /// <param name="validator">A new caller-disposed validator on success; otherwise null.</param>
    /// <returns>Done, or InvalidData for an unknown format or nonzero extended checksum.</returns>
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

    /// <summary>Retrieves the full digest only after successful completion when hashing was enabled.</summary>
    /// <param name="payloadDoubleSha256">The digest on success; otherwise default.</param>
    /// <returns>Done if a validated digest is available; otherwise InvalidData.</returns>
    /// <exception cref="ObjectDisposedException">The validator has been disposed.</exception>
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

    /// <summary>Consumes up to the remaining declared payload length, leaving following bytes untouched.</summary>
    /// <param name="source">Caller-owned payload bytes, used only during this call.</param>
    /// <param name="bytesConsumed">Bytes accepted from this call, including bytes accepted before checksum failure.</param>
    /// <returns>NeedMoreData while bytes remain; Done on successful final validation; InvalidData for checksum failure or any call after completion.</returns>
    /// <remarks>A zero-length payload is finalized by calling this method with an empty span. Final success or failure is terminal; the validator cannot be reused.</remarks>
    /// <exception cref="ObjectDisposedException">The validator has been disposed.</exception>
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

    /// <summary>Releases incremental hash resources without completing or validating an unfinished payload; repeated disposal is harmless.</summary>
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
