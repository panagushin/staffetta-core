using System.Buffers;
using System.Buffers.Binary;

namespace Staffetta.Core.Protocol.Handshake;

/// <summary>Encodes the strict eight-byte little-endian nonce form of modern ping and pong payloads.</summary>
public static class ModernPingPongPayloadCodec
{
    /// <summary>The exact nonce payload length in bytes.</summary>
    public const int EncodedLength = sizeof(ulong);

    /// <summary>Reads a complete ping or pong payload containing exactly one nonce.</summary>
    /// <param name="source">The complete caller-owned payload; not retained.</param>
    /// <param name="nonce">The decoded nonce on success; otherwise zero.</param>
    /// <returns>Done for exactly eight bytes, NeedMoreData for fewer bytes, or InvalidData for trailing bytes.</returns>
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

    /// <summary>Writes a nonce as eight little-endian bytes into caller-owned storage.</summary>
    /// <param name="destination">Storage for at least eight bytes.</param>
    /// <param name="nonce">The caller-supplied nonce to encode.</param>
    /// <param name="bytesWritten">Eight on success; otherwise zero.</param>
    /// <returns>Done, or DestinationTooSmall without modifying the destination.</returns>
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
