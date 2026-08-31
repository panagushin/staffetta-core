using System.Buffers;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Encoding;

namespace Staffetta.Core.Protocol.Messages;

/// <summary>
/// Encodes the bounded Staffetta BSV interoperability profile for reject payloads. Its limits are
/// denial-of-service and compatibility policy, not protocol-wide BIP61 wire limits.
/// </summary>
public static class RejectPayloadCodec
{
    public const int MaximumCommandLength = 12;
    public const int MaximumReasonLength = 111;
    public const int MaximumDataLength = Hash256.Length;
    public const int MaximumPayloadLength =
        1 + MaximumCommandLength + sizeof(byte) + 1 + MaximumReasonLength + MaximumDataLength;

    public static OperationStatus TryParse(
        ReadOnlySpan<byte> source,
        out RejectPayload payload,
        out int bytesConsumed)
    {
        payload = default;
        bytesConsumed = 0;
        if (source.Length > MaximumPayloadLength)
        {
            return OperationStatus.InvalidData;
        }

        var commandStatus = ReadBoundedBytes(
            source,
            MaximumCommandLength,
            out var command,
            out var commandLength);
        if (commandStatus != OperationStatus.Done)
        {
            return commandStatus;
        }

        if (source.Length == commandLength)
        {
            return OperationStatus.NeedMoreData;
        }

        var code = source[commandLength];
        var offset = commandLength + sizeof(byte);
        var reasonStatus = ReadBoundedBytes(
            source[offset..],
            MaximumReasonLength,
            out var reason,
            out var reasonLength);
        if (reasonStatus != OperationStatus.Done)
        {
            return reasonStatus;
        }

        offset += reasonLength;
        var data = source[offset..];
        var dataStatus = ValidateData(command, data.Length);
        if (dataStatus != OperationStatus.Done)
        {
            return dataStatus;
        }

        payload = new RejectPayload(command, code, reason, data);
        bytesConsumed = source.Length;
        return OperationStatus.Done;
    }

    public static OperationStatus TryWrite(
        Span<byte> destination,
        ReadOnlySpan<byte> command,
        byte code,
        ReadOnlySpan<byte> reason,
        ReadOnlySpan<byte> data,
        out int bytesWritten)
    {
        bytesWritten = 0;
        if (command.Length > MaximumCommandLength || reason.Length > MaximumReasonLength)
        {
            return OperationStatus.InvalidData;
        }

        var dataStatus = ValidateData(command, data.Length);
        if (dataStatus != OperationStatus.Done)
        {
            return OperationStatus.InvalidData;
        }

        var requiredLength =
            1 + command.Length + sizeof(byte) + 1 + reason.Length + data.Length;
        if (destination.Length < requiredLength)
        {
            return OperationStatus.DestinationTooSmall;
        }

        var offset = 0;
        _ = CompactSize.Write((ulong)command.Length, destination, out var commandPrefixLength);
        offset += commandPrefixLength;
        command.CopyTo(destination[offset..]);
        offset += command.Length;
        destination[offset] = code;
        offset += sizeof(byte);
        _ = CompactSize.Write((ulong)reason.Length, destination[offset..], out var reasonPrefixLength);
        offset += reasonPrefixLength;
        reason.CopyTo(destination[offset..]);
        offset += reason.Length;
        data.CopyTo(destination[offset..]);

        bytesWritten = requiredLength;
        return OperationStatus.Done;
    }

    private static OperationStatus ReadBoundedBytes(
        ReadOnlySpan<byte> source,
        int maximumLength,
        out ReadOnlySpan<byte> value,
        out int bytesConsumed)
    {
        value = default;
        bytesConsumed = 0;
        var lengthStatus = CompactSize.Read(source, out var encodedLength, out var prefixLength);
        if (lengthStatus != OperationStatus.Done)
        {
            return lengthStatus;
        }

        if (encodedLength > (ulong)maximumLength)
        {
            return OperationStatus.InvalidData;
        }

        var length = (int)encodedLength;
        if (source.Length - prefixLength < length)
        {
            return OperationStatus.NeedMoreData;
        }

        value = source.Slice(prefixLength, length);
        bytesConsumed = prefixLength + length;
        return OperationStatus.Done;
    }

    private static OperationStatus ValidateData(ReadOnlySpan<byte> command, int dataLength)
    {
        if (command.SequenceEqual("version"u8))
        {
            return dataLength == 0 ? OperationStatus.Done : OperationStatus.InvalidData;
        }

        if (command.SequenceEqual("tx"u8) || command.SequenceEqual("block"u8))
        {
            return dataLength switch
            {
                < Hash256.Length => OperationStatus.NeedMoreData,
                Hash256.Length => OperationStatus.Done,
                _ => OperationStatus.InvalidData,
            };
        }

        return dataLength <= MaximumDataLength
            ? OperationStatus.Done
            : OperationStatus.InvalidData;
    }
}
