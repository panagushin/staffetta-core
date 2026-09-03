using System.Buffers;

namespace Staffetta.Core.Protocol.Handshake;

/// <summary>Validates and writes the strictly empty verack payload.</summary>
public static class VerackPayloadCodec
{
    /// <summary>Checks that the complete caller-owned verack payload is empty.</summary>
    /// <returns>Done for an empty span; otherwise InvalidData.</returns>
    public static OperationStatus TryParse(ReadOnlySpan<byte> source) =>
        source.IsEmpty ? OperationStatus.Done : OperationStatus.InvalidData;

    /// <summary>Writes the empty verack payload without modifying the destination.</summary>
    /// <param name="destination">Caller-owned storage; unused and not retained.</param>
    /// <param name="bytesWritten">Always zero.</param>
    /// <returns>Always Done.</returns>
    public static OperationStatus TryWrite(Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        return OperationStatus.Done;
    }
}
