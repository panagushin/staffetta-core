using System.Buffers;
using Staffetta.Core.Protocol.Encoding;

namespace Staffetta.Core.Protocol.Messages;

public static class InventoryPayloadCodec
{
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
