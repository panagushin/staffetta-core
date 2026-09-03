using System.Buffers;
using System.Buffers.Binary;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Messages;

/// <summary>Reads and writes raw inventory entries without rejecting unknown inventory types.</summary>
public static class InventoryVectorCodec
{
    /// <summary>The 36-byte length of a type and wire-order object hash.</summary>
    public const int EncodedLength = sizeof(uint) + Hash256.Length;

    /// <summary>Copies one vector from the start of the source, leaving trailing bytes unconsumed.</summary>
    /// <param name="source">Bytes beginning with a 4-byte little-endian type and 32-byte wire-order hash.</param>
    /// <param name="vector">The decoded entry on success; otherwise the default value.</param>
    /// <param name="bytesConsumed">36 on success; otherwise zero.</param>
    /// <returns><see cref="OperationStatus.Done"/> or <see cref="OperationStatus.NeedMoreData"/>.</returns>
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

    /// <summary>Writes one vector, leaving an undersized destination unchanged.</summary>
    /// <param name="vector">The raw type and object identifier to serialize.</param>
    /// <param name="destination">Storage for at least 36 bytes; trailing bytes are untouched.</param>
    /// <param name="bytesWritten">36 on success; otherwise zero.</param>
    /// <returns><see cref="OperationStatus.Done"/> or <see cref="OperationStatus.DestinationTooSmall"/>.</returns>
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
