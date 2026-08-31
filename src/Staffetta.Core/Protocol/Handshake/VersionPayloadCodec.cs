using System.Buffers;
using System.Buffers.Binary;
using Staffetta.Core.Protocol.Encoding;

namespace Staffetta.Core.Protocol.Handshake;

public static class VersionPayloadCodec
{
    public const int CurrentProtocolVersion = 70_016;
    public const int MaximumUserAgentLength = 256;
    public const int MaximumAssociationIdLength = 129;
    public const int RequiredPrefixLength =
        sizeof(int) + sizeof(ulong) + sizeof(long) + NetworkAddressCodec.EncodedLength;

    private const int SourceAndNonceLength = NetworkAddressCodec.EncodedLength + sizeof(ulong);

    public static OperationStatus TryParse(
        ReadOnlySpan<byte> source,
        out VersionPayload payload,
        out int bytesConsumed)
    {
        payload = default;
        bytesConsumed = 0;
        if (source.Length < RequiredPrefixLength)
        {
            return OperationStatus.NeedMoreData;
        }

        var protocolVersion = BinaryPrimitives.ReadInt32LittleEndian(source);
        var services = BinaryPrimitives.ReadUInt64LittleEndian(source[sizeof(int)..]);
        var timestampOffset = sizeof(int) + sizeof(ulong);
        var timestamp = BinaryPrimitives.ReadInt64LittleEndian(source[timestampOffset..]);
        var receivingOffset = timestampOffset + sizeof(long);
        var receivingStatus = NetworkAddressCodec.TryParse(
            source[receivingOffset..],
            out var receivingAddress,
            out _);
        if (receivingStatus != OperationStatus.Done)
        {
            return receivingStatus;
        }

        if (source.Length == RequiredPrefixLength)
        {
            payload = CreateParsed(
                protocolVersion,
                services,
                timestamp,
                receivingAddress,
                sourceAddress: default,
                hasSourceAddress: false,
                nonce: 0,
                userAgent: default,
                hasUserAgent: false,
                startHeight: 0,
                hasStartHeight: false,
                relay: true,
                hasRelay: false,
                associationId: default,
                hasAssociationId: false);
            bytesConsumed = source.Length;
            return OperationStatus.Done;
        }

        if (source.Length < RequiredPrefixLength + SourceAndNonceLength)
        {
            return OperationStatus.NeedMoreData;
        }

        var offset = RequiredPrefixLength;
        var sourceStatus = NetworkAddressCodec.TryParse(
            source[offset..],
            out var sourceAddress,
            out var sourceLength);
        if (sourceStatus != OperationStatus.Done)
        {
            return sourceStatus;
        }

        offset += sourceLength;
        var nonce = BinaryPrimitives.ReadUInt64LittleEndian(source[offset..]);
        offset += sizeof(ulong);

        if (source.Length == offset)
        {
            payload = CreateParsed(
                protocolVersion,
                services,
                timestamp,
                receivingAddress,
                sourceAddress,
                hasSourceAddress: true,
                nonce,
                userAgent: default,
                hasUserAgent: false,
                startHeight: 0,
                hasStartHeight: false,
                relay: true,
                hasRelay: false,
                associationId: default,
                hasAssociationId: false);
            bytesConsumed = source.Length;
            return OperationStatus.Done;
        }

        var userAgentStatus = ReadBoundedBytes(
            source[offset..],
            MaximumUserAgentLength,
            out var userAgent,
            out var userAgentLength);
        if (userAgentStatus != OperationStatus.Done)
        {
            return userAgentStatus;
        }

        offset += userAgentLength;
        if (source.Length == offset)
        {
            payload = CreateParsed(
                protocolVersion,
                services,
                timestamp,
                receivingAddress,
                sourceAddress,
                hasSourceAddress: true,
                nonce,
                userAgent,
                hasUserAgent: true,
                startHeight: 0,
                hasStartHeight: false,
                relay: true,
                hasRelay: false,
                associationId: default,
                hasAssociationId: false);
            bytesConsumed = source.Length;
            return OperationStatus.Done;
        }

        if (source.Length < offset + sizeof(int))
        {
            return OperationStatus.NeedMoreData;
        }

        var startHeight = BinaryPrimitives.ReadInt32LittleEndian(source[offset..]);
        offset += sizeof(int);
        if (source.Length == offset)
        {
            payload = CreateParsed(
                protocolVersion,
                services,
                timestamp,
                receivingAddress,
                sourceAddress,
                hasSourceAddress: true,
                nonce,
                userAgent,
                hasUserAgent: true,
                startHeight,
                hasStartHeight: true,
                relay: true,
                hasRelay: false,
                associationId: default,
                hasAssociationId: false);
            bytesConsumed = source.Length;
            return OperationStatus.Done;
        }

        var relayByte = source[offset];
        if (relayByte > 1)
        {
            return OperationStatus.InvalidData;
        }

        var relay = relayByte == 1;
        offset++;
        if (source.Length == offset)
        {
            payload = CreateParsed(
                protocolVersion,
                services,
                timestamp,
                receivingAddress,
                sourceAddress,
                hasSourceAddress: true,
                nonce,
                userAgent,
                hasUserAgent: true,
                startHeight,
                hasStartHeight: true,
                relay,
                hasRelay: true,
                associationId: default,
                hasAssociationId: false);
            bytesConsumed = source.Length;
            return OperationStatus.Done;
        }

        var associationStatus = ReadBoundedBytes(
            source[offset..],
            MaximumAssociationIdLength,
            out var associationId,
            out var associationLength);
        if (associationStatus != OperationStatus.Done)
        {
            return associationStatus;
        }

        offset += associationLength;
        if (source.Length != offset)
        {
            return OperationStatus.InvalidData;
        }

        payload = CreateParsed(
            protocolVersion,
            services,
            timestamp,
            receivingAddress,
            sourceAddress,
            hasSourceAddress: true,
            nonce,
            userAgent,
            hasUserAgent: true,
            startHeight,
            hasStartHeight: true,
            relay,
            hasRelay: true,
            associationId,
            hasAssociationId: true);
        bytesConsumed = source.Length;
        return OperationStatus.Done;
    }

    public static OperationStatus TryWrite(
        Span<byte> destination,
        VersionPayload payload,
        out int bytesWritten)
    {
        bytesWritten = 0;
        if (!payload.HasSourceAddress ||
            !payload.HasUserAgent ||
            !payload.HasStartHeight ||
            !payload.HasRelay ||
            payload.UserAgent.Length > MaximumUserAgentLength ||
            payload.AssociationId.Length > MaximumAssociationIdLength)
        {
            return OperationStatus.InvalidData;
        }

        var associationPrefixLength = payload.HasAssociationId
            ? GetCompactSizeLength((ulong)payload.AssociationId.Length)
            : 0;
        var requiredLength = checked(
            RequiredPrefixLength +
            SourceAndNonceLength +
            GetCompactSizeLength((ulong)payload.UserAgent.Length) +
            payload.UserAgent.Length +
            sizeof(int) +
            sizeof(byte) +
            associationPrefixLength +
            payload.AssociationId.Length);
        if (destination.Length < requiredLength)
        {
            return OperationStatus.DestinationTooSmall;
        }

        BinaryPrimitives.WriteInt32LittleEndian(destination, payload.ProtocolVersion);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[sizeof(int)..], payload.Services);
        var offset = sizeof(int) + sizeof(ulong);
        BinaryPrimitives.WriteInt64LittleEndian(destination[offset..], payload.TimestampUnixSeconds);
        offset += sizeof(long);
        NetworkAddressCodec.TryWrite(destination[offset..], payload.ReceivingAddress, out var addressLength);
        offset += addressLength;
        NetworkAddressCodec.TryWrite(destination[offset..], payload.SourceAddress, out addressLength);
        offset += addressLength;
        BinaryPrimitives.WriteUInt64LittleEndian(destination[offset..], payload.Nonce);
        offset += sizeof(ulong);
        CompactSize.Write((ulong)payload.UserAgent.Length, destination[offset..], out var prefixLength);
        offset += prefixLength;
        payload.UserAgent.CopyTo(destination[offset..]);
        offset += payload.UserAgent.Length;
        BinaryPrimitives.WriteInt32LittleEndian(destination[offset..], payload.StartHeight);
        offset += sizeof(int);
        destination[offset] = payload.Relay ? (byte)1 : (byte)0;
        offset++;

        if (payload.HasAssociationId)
        {
            CompactSize.Write((ulong)payload.AssociationId.Length, destination[offset..], out prefixLength);
            offset += prefixLength;
            payload.AssociationId.CopyTo(destination[offset..]);
            offset += payload.AssociationId.Length;
        }

        bytesWritten = offset;
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

    private static VersionPayload CreateParsed(
        int protocolVersion,
        ulong services,
        long timestamp,
        NetworkAddress receivingAddress,
        NetworkAddress sourceAddress,
        bool hasSourceAddress,
        ulong nonce,
        ReadOnlySpan<byte> userAgent,
        bool hasUserAgent,
        int startHeight,
        bool hasStartHeight,
        bool relay,
        bool hasRelay,
        ReadOnlySpan<byte> associationId,
        bool hasAssociationId) =>
        new(
            protocolVersion,
            services,
            timestamp,
            receivingAddress,
            sourceAddress,
            hasSourceAddress,
            nonce,
            userAgent,
            hasUserAgent,
            startHeight,
            hasStartHeight,
            relay,
            hasRelay,
            associationId,
            hasAssociationId);

    private static int GetCompactSizeLength(ulong value) => value switch
    {
        < 0xfd => 1,
        <= ushort.MaxValue => 3,
        <= uint.MaxValue => 5,
        _ => 9,
    };
}
