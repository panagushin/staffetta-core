using System.Buffers;
using System.Buffers.Binary;

namespace Staffetta.Core.Protocol.Handshake;

public static class NetworkAddressCodec
{
    public const int EncodedLength = 26;

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
