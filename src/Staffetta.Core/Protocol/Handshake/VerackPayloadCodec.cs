using System.Buffers;

namespace Staffetta.Core.Protocol.Handshake;

public static class VerackPayloadCodec
{
    public static OperationStatus TryParse(ReadOnlySpan<byte> source) =>
        source.IsEmpty ? OperationStatus.Done : OperationStatus.InvalidData;

    public static OperationStatus TryWrite(Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        return OperationStatus.Done;
    }
}
