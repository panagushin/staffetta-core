using System.Buffers;
using Staffetta.Core.Protocol.Encoding;

namespace Staffetta.Core.Protocol.Messages;

/// <summary>
/// Incrementally parses an inventory payload into caller-owned bounded storage.
/// </summary>
/// <remarks>
/// Instances are single-consumer and not thread-safe. A full destination stops consumption before
/// any byte of the next vector. Reset establishes the exact enclosing payload length and clears a
/// prior successful parse; malformed input and incomplete completion remain faulted until reset.
/// </remarks>
public sealed class IncrementalInventoryPayloadParser
{
    private readonly byte[] _scratch = new byte[InventoryVectorCodec.EncodedLength];

    private IncrementalCompactSizeReader _compactSize;
    private ParseState _state;
    private ulong _declaredPayloadLength;
    private ulong _vectorCount;
    private ulong _vectorsRead;
    private int _countLength;
    private int _scratchLength;

    public ulong VectorCount => _vectorCount;

    public ulong VectorsRead => _vectorsRead;

    /// <summary>Begins a payload whose exact byte length is supplied by the enclosing frame.</summary>
    public void Reset(ulong declaredPayloadLength)
    {
        _scratch.AsSpan(0, _scratchLength).Clear();
        _compactSize = default;
        _state = ParseState.Count;
        _declaredPayloadLength = declaredPayloadLength;
        _vectorCount = 0;
        _vectorsRead = 0;
        _countLength = 0;
        _scratchLength = 0;
    }

    /// <summary>Consumes payload bytes until input, output capacity, or the exact payload ends.</summary>
    public OperationStatus Consume(
        ReadOnlySpan<byte> source,
        Span<InventoryVector> destination,
        out int bytesConsumed,
        out int vectorsWritten)
    {
        bytesConsumed = 0;
        vectorsWritten = 0;
        if (_state is ParseState.Uninitialized or ParseState.Faulted)
        {
            return OperationStatus.InvalidData;
        }

        if (_state == ParseState.Completed)
        {
            return OperationStatus.Done;
        }

        if (_state == ParseState.Count)
        {
            var countBytesConsumed = _compactSize.Consume(source);
            bytesConsumed += countBytesConsumed;
            _countLength += countBytesConsumed;
            if (!_compactSize.IsComplete)
            {
                return OperationStatus.NeedMoreData;
            }

            if (!_compactSize.IsCanonical || !HasExactPayloadLength(_compactSize.Value))
            {
                _state = ParseState.Faulted;
                return OperationStatus.InvalidData;
            }

            _vectorCount = _compactSize.Value;
            _compactSize = default;
            if (_vectorCount == 0)
            {
                _state = ParseState.Completed;
                return OperationStatus.Done;
            }

            _state = ParseState.Vectors;
        }

        while (_vectorsRead < _vectorCount)
        {
            if (vectorsWritten == destination.Length)
            {
                return OperationStatus.DestinationTooSmall;
            }

            var copiedLength = Math.Min(
                source.Length - bytesConsumed,
                InventoryVectorCodec.EncodedLength - _scratchLength);
            if (copiedLength == 0)
            {
                return OperationStatus.NeedMoreData;
            }

            source.Slice(bytesConsumed, copiedLength).CopyTo(_scratch.AsSpan(_scratchLength));
            _scratchLength += copiedLength;
            bytesConsumed += copiedLength;
            if (_scratchLength < InventoryVectorCodec.EncodedLength)
            {
                return OperationStatus.NeedMoreData;
            }

            _ = InventoryVectorCodec.TryParse(_scratch, out destination[vectorsWritten], out _);
            _scratch.AsSpan().Clear();
            _scratchLength = 0;
            vectorsWritten++;
            _vectorsRead++;
        }

        _state = ParseState.Completed;
        return OperationStatus.Done;
    }

    /// <summary>Marks the enclosing payload complete and rejects truncation.</summary>
    public OperationStatus Complete()
    {
        if (_state == ParseState.Completed)
        {
            return OperationStatus.Done;
        }

        _state = ParseState.Faulted;
        return OperationStatus.InvalidData;
    }

    private bool HasExactPayloadLength(ulong count)
    {
        var prefixLength = (ulong)_countLength;
        if (count > (ulong.MaxValue - prefixLength) / InventoryVectorCodec.EncodedLength)
        {
            return false;
        }

        return prefixLength + (count * InventoryVectorCodec.EncodedLength) ==
            _declaredPayloadLength;
    }

    private enum ParseState
    {
        Uninitialized,
        Count,
        Vectors,
        Completed,
        Faulted,
    }
}
