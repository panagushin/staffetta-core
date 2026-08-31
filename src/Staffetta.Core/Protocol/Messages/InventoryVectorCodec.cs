using System.Buffers;
using System.Buffers.Binary;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Messages;

public static class InventoryVectorCodec
{
    public const int EncodedLength = sizeof(uint) + Hash256.Length;

    public static OperationStatus TryParse(
        ReadOnlySpan<byte> source,
        out InventoryVector vector,
        out int bytesConsumed)
    {
        vector = default;
        bytesConsumed = 0;
        if (source.Length < EncodedLength)
        {
            return OperationStatus.NeedMoreData;
        }

        vector = new InventoryVector(
            BinaryPrimitives.ReadUInt32LittleEndian(source),
            Hash256.FromWireBytes(source.Slice(sizeof(uint), Hash256.Length)));
        bytesConsumed = EncodedLength;
        return OperationStatus.Done;
    }

    public static OperationStatus TryWrite(
        in InventoryVector vector,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = 0;
        if (destination.Length < EncodedLength)
        {
            return OperationStatus.DestinationTooSmall;
        }

        BinaryPrimitives.WriteUInt32LittleEndian(destination, vector.Type);
        vector.Hash.WriteWireBytesTo(destination[sizeof(uint)..]);
        bytesWritten = EncodedLength;
        return OperationStatus.Done;
    }
}
