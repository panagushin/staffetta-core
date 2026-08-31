using System.Buffers;
using System.Buffers.Binary;

namespace Staffetta.Core.Protocol.Handshake;

public static class ModernPingPongPayloadCodec
{
    public const int EncodedLength = sizeof(ulong);

    public static OperationStatus TryParse(ReadOnlySpan<byte> source, out ulong nonce)
    {
        nonce = 0;
        if (source.Length < EncodedLength)
        {
            return OperationStatus.NeedMoreData;
        }

        if (source.Length != EncodedLength)
        {
            return OperationStatus.InvalidData;
        }

        nonce = BinaryPrimitives.ReadUInt64LittleEndian(source);
        return OperationStatus.Done;
    }

    public static OperationStatus TryWrite(
        Span<byte> destination,
        ulong nonce,
        out int bytesWritten)
    {
        bytesWritten = 0;
        if (destination.Length < EncodedLength)
        {
            return OperationStatus.DestinationTooSmall;
        }

        BinaryPrimitives.WriteUInt64LittleEndian(destination, nonce);
        bytesWritten = EncodedLength;
        return OperationStatus.Done;
    }
}
