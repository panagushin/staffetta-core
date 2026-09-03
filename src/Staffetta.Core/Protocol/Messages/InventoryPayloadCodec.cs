using System.Buffers;
using Staffetta.Core.Protocol.Encoding;

namespace Staffetta.Core.Protocol.Messages;

/// <summary>Writes canonical inventory-list payloads under a caller-supplied byte limit.</summary>
public static class InventoryPayloadCodec
{
    /// <summary>Writes a count and vectors, leaving the destination unchanged on failure.</summary>
    /// <param name="vectors">Entries in wire order; unknown types are preserved.</param>
    /// <param name="destination">Output storage; bytes beyond the payload are untouched.</param>
    /// <param name="maximumPayloadLength">The caller's inclusive payload-byte limit, including the count prefix.</param>
    /// <param name="bytesWritten">The payload length on success; otherwise zero.</param>
    /// <returns>
    /// <see cref="OperationStatus.Done"/>, <see cref="OperationStatus.InvalidData"/> if the byte limit
    /// would be exceeded, or <see cref="OperationStatus.DestinationTooSmall"/> for insufficient storage.
    /// </returns>
    public static OperationStatus TryWrite(
        ReadOnlySpan<InventoryVector> vectors,
        Span<byte> destination,
        ulong maximumPayloadLength,
        out int bytesWritten)
    {
        bytesWritten = 0;
        Span<byte> encodedCount = stackalloc byte[sizeof(ulong) + 1];
        _ = CompactSize.Write((ulong)vectors.Length, encodedCount, out var countLength);

        var requiredLength = checked(
            (ulong)countLength + ((ulong)vectors.Length * InventoryVectorCodec.EncodedLength));
        if (requiredLength > maximumPayloadLength)
        {
            return OperationStatus.InvalidData;
        }

        if (requiredLength > (ulong)destination.Length)
        {
            return OperationStatus.DestinationTooSmall;
        }

        encodedCount[..countLength].CopyTo(destination);
        var offset = countLength;
        foreach (ref readonly var vector in vectors)
        {
            _ = InventoryVectorCodec.TryWrite(vector, destination[offset..], out var vectorLength);
            offset += vectorLength;
        }

        bytesWritten = offset;
        return OperationStatus.Done;
    }
}
