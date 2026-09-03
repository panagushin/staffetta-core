using System.Buffers;
using System.Buffers.Binary;
using Staffetta.Core.Protocol.Encoding;

namespace Staffetta.Core.Protocol.Handshake;

/// <summary>Parses bounded protoconf payloads and writes one- or two-field advertisements.</summary>
public static class ProtoconfPayloadCodec
{
    /// <summary>The inclusive maximum complete protoconf payload length in bytes.</summary>
    public const int MaximumPayloadLength = 1_048_576;
    /// <summary>The maximum stream-policy byte length, excluding its CompactSize prefix.</summary>
    public const int MaximumStreamPoliciesLength = 650;

    /// <summary>Parses one complete protoconf payload without copying policy or future-field bytes.</summary>
    /// <param name="source">The complete payload; returned spans borrow this storage.</param>
    /// <param name="payload">The parsed view on success; otherwise default.</param>
    /// <param name="bytesConsumed">The source length on success; otherwise zero.</param>
    /// <returns>Done, NeedMoreData for incomplete known fields, or InvalidData for invalid counts, noncanonical lengths, exceeded bounds, or unexpected known-field trailing bytes.</returns>
    /// <remarks>Counts above two expose trailing bytes opaquely without validating future-field structure. This codec does not enforce the handshake receive-limit minimum.</remarks>
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

    /// <summary>Writes the receive limit and an optional bounded policy field using canonical CompactSize lengths.</summary>
    /// <param name="destination">Caller-owned output storage.</param>
    /// <param name="maximumReceivePayloadLength">The advertised limit in bytes; no handshake-policy minimum is enforced here.</param>
    /// <param name="streamPolicies">Caller-owned unprefixed policy bytes; not retained.</param>
    /// <param name="includeStreamPolicies">Whether to emit a second field, including an empty policy field.</param>
    /// <param name="bytesWritten">The encoded length on success; otherwise zero.</param>
    /// <returns>Done, InvalidData for oversized or excluded nonempty policies, or DestinationTooSmall. Non-success leaves the destination unchanged.</returns>
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
