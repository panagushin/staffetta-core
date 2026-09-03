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
/// Output vectors are copied values but remain provisional until the enclosing frame is validated;
/// this parser checks count/length consistency, not checksums or the meaning of inventory types.
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

    /// <summary>Gets the declared vector count after a canonical, length-consistent prefix; zero before then.</summary>
    public ulong VectorCount => _vectorCount;

    /// <summary>Gets the number of complete vectors emitted since the last reset.</summary>
    public ulong VectorsRead => _vectorsRead;

    /// <summary>Begins a payload whose exact byte length is supplied by the enclosing frame.</summary>
    /// <param name="declaredPayloadLength">The exact payload length in bytes, including the count prefix.</param>
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
    /// <param name="source">The next input chunk; any bytes after the complete payload are unconsumed.</param>
    /// <param name="destination">Caller-owned storage for complete vectors produced by this call.</param>
    /// <param name="bytesConsumed">Bytes accepted from this chunk, including buffered partial fields.</param>
    /// <param name="vectorsWritten">Complete vectors written by this call, including on a partial result.</param>
    /// <returns>
    /// <see cref="OperationStatus.Done"/> when the payload is complete;
    /// <see cref="OperationStatus.NeedMoreData"/> when a field is incomplete;
    /// <see cref="OperationStatus.DestinationTooSmall"/> when output is full; or
    /// <see cref="OperationStatus.InvalidData"/> before reset, after a fault, or for an invalid count/length.
    /// </returns>
    /// <remarks>
    /// Resume partial results with the unconsumed source suffix and fresh output capacity. A completed
    /// parser returns Done without consuming further bytes until reset. Source spans are not retained.
    /// </remarks>
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
    /// <returns><see cref="OperationStatus.Done"/> if already complete; otherwise faults the parser and returns <see cref="OperationStatus.InvalidData"/>.</returns>
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
