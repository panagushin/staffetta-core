using System.Buffers;
using System.Buffers.Binary;

namespace Staffetta.Core.Protocol.Handshake;

/// <summary>Encodes timestamp-free network addresses with little-endian services and a big-endian port.</summary>
public static class NetworkAddressCodec
{
    /// <summary>The encoded service/address/port length in bytes, excluding any timestamp.</summary>
    public const int EncodedLength = 26;

    /// <summary>Parses one fixed-size address prefix and copies its fields into a value.</summary>
    /// <param name="source">Caller-owned bytes beginning with a timestamp-free network address; not retained.</param>
    /// <param name="address">The copied address on success; otherwise default.</param>
    /// <param name="bytesConsumed">Twenty-six on success; otherwise zero. Trailing bytes are untouched.</param>
    /// <returns>Done, or NeedMoreData when fewer than twenty-six bytes are available.</returns>
    public static OperationStatus TryParse(
        ReadOnlySpan<byte> source,
        out NetworkAddress address,
        out int bytesConsumed)
    {
        address = default;
        bytesConsumed = 0;
        if (source.Length < EncodedLength)
        {
            return OperationStatus.NeedMoreData;
        }

        var services = BinaryPrimitives.ReadUInt64LittleEndian(source);
        var port = BinaryPrimitives.ReadUInt16BigEndian(source[24..]);
        address = new NetworkAddress(services, source.Slice(8, 16), port);
        bytesConsumed = EncodedLength;
        return OperationStatus.Done;
    }

    /// <summary>Writes one fixed-size timestamp-free network address into caller-owned storage.</summary>
    /// <param name="destination">Storage for twenty-six encoded bytes.</param>
    /// <param name="address">The address value to encode.</param>
    /// <param name="bytesWritten">Twenty-six on success; otherwise zero.</param>
    /// <returns>Done, or DestinationTooSmall without modifying the destination.</returns>
    public static OperationStatus TryWrite(
        Span<byte> destination,
        NetworkAddress address,
        out int bytesWritten)
    {
        bytesWritten = 0;
        if (destination.Length < EncodedLength)
        {
            return OperationStatus.DestinationTooSmall;
        }

        BinaryPrimitives.WriteUInt64LittleEndian(destination, address.Services);
        address.TryWriteAddress(destination.Slice(8, 16));
        BinaryPrimitives.WriteUInt16BigEndian(destination[24..], address.Port);
        bytesWritten = EncodedLength;
        return OperationStatus.Done;
    }
}
