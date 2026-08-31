using System.Buffers;
using System.Buffers.Binary;
using Staffetta.Core.Protocol.Encoding;

namespace Staffetta.Core.Protocol.Handshake;

public static class ProtoconfPayloadCodec
{
    public const int MaximumPayloadLength = 1_048_576;
    public const int MaximumStreamPoliciesLength = 650;

    public static OperationStatus TryParse(
        ReadOnlySpan<byte> source,
        out ProtoconfPayload payload,
        out int bytesConsumed)
    {
        payload = default;
        bytesConsumed = 0;
        if (source.Length > MaximumPayloadLength)
        {
            return OperationStatus.InvalidData;
        }

        var countStatus = CompactSize.Read(source, out var fieldCount, out var countLength);
        if (countStatus != OperationStatus.Done)
        {
            return countStatus;
        }

        if (fieldCount == 0)
        {
            return OperationStatus.InvalidData;
        }

        if (source.Length < countLength + sizeof(uint))
        {
            return OperationStatus.NeedMoreData;
        }

        var maximumReceivePayloadLength = BinaryPrimitives.ReadUInt32LittleEndian(source[countLength..]);
        var offset = countLength + sizeof(uint);
        if (fieldCount == 1)
        {
            if (source.Length != offset)
            {
                return OperationStatus.InvalidData;
            }

            payload = new ProtoconfPayload(
                fieldCount,
                maximumReceivePayloadLength,
                streamPolicies: default,
                additionalFields: default);
            bytesConsumed = offset;
            return OperationStatus.Done;
        }

        var policyStatus = ReadStreamPolicies(
            source[offset..],
            out var streamPolicies,
            out var policyLength);
        if (policyStatus != OperationStatus.Done)
        {
            return policyStatus;
        }

        offset += policyLength;
        if (fieldCount == 2 && source.Length != offset)
        {
            return OperationStatus.InvalidData;
        }

        payload = new ProtoconfPayload(
            fieldCount,
            maximumReceivePayloadLength,
            streamPolicies,
            source[offset..]);
        bytesConsumed = source.Length;
        return OperationStatus.Done;
    }

    public static OperationStatus TryWrite(
        Span<byte> destination,
        uint maximumReceivePayloadLength,
        ReadOnlySpan<byte> streamPolicies,
        bool includeStreamPolicies,
        out int bytesWritten)
    {
        bytesWritten = 0;
        if ((!includeStreamPolicies && !streamPolicies.IsEmpty) ||
            streamPolicies.Length > MaximumStreamPoliciesLength)
        {
            return OperationStatus.InvalidData;
        }

        var requiredLength = 1 + sizeof(uint);
        if (includeStreamPolicies)
        {
            requiredLength += GetCompactSizeLength((ulong)streamPolicies.Length) + streamPolicies.Length;
        }

        if (destination.Length < requiredLength)
        {
            return OperationStatus.DestinationTooSmall;
        }

        destination[0] = includeStreamPolicies ? (byte)2 : (byte)1;
        BinaryPrimitives.WriteUInt32LittleEndian(destination[1..], maximumReceivePayloadLength);
        if (includeStreamPolicies)
        {
            var offset = 1 + sizeof(uint);
            CompactSize.Write((ulong)streamPolicies.Length, destination[offset..], out var prefixLength);
            offset += prefixLength;
            streamPolicies.CopyTo(destination[offset..]);
        }

        bytesWritten = requiredLength;
        return OperationStatus.Done;
    }

    private static OperationStatus ReadStreamPolicies(
        ReadOnlySpan<byte> source,
        out ReadOnlySpan<byte> streamPolicies,
        out int bytesConsumed)
    {
        streamPolicies = default;
        bytesConsumed = 0;
        var lengthStatus = CompactSize.Read(source, out var encodedLength, out var prefixLength);
        if (lengthStatus != OperationStatus.Done)
        {
            return lengthStatus;
        }

        if (encodedLength > MaximumStreamPoliciesLength)
        {
            return OperationStatus.InvalidData;
        }

        var length = (int)encodedLength;
        if (source.Length - prefixLength < length)
        {
            return OperationStatus.NeedMoreData;
        }

        streamPolicies = source.Slice(prefixLength, length);
        bytesConsumed = prefixLength + length;
        return OperationStatus.Done;
    }

    private static int GetCompactSizeLength(ulong value) => value switch
    {
        < 0xfd => 1,
        <= ushort.MaxValue => 3,
        <= uint.MaxValue => 5,
        _ => 9,
    };
}
