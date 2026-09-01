using System.Buffers;
using System.Buffers.Binary;
using Staffetta.Core.Protocol.Encoding;
using Staffetta.Core.Protocol.Handshake;

namespace Staffetta.Core.Protocol.Discovery;

public static class LegacyAddressPayloadCodec
{
    public const int MaximumRecordCount = 1_000;
    public const int RecordLength = sizeof(uint) + NetworkAddressCodec.EncodedLength;
    public const int MaximumPayloadLength = 3 + (MaximumRecordCount * RecordLength);

    public static OperationStatus TryParse(
        ReadOnlySpan<byte> source,
        Span<LegacyAddressRecord> destination,
        out int recordsWritten,
        out int bytesConsumed)
    {
        recordsWritten = 0;
        bytesConsumed = 0;

        var countStatus = CompactSize.Read(source, out var count, out var countLength);
        if (countStatus != OperationStatus.Done)
        {
            return countStatus;
        }

        if (count > MaximumRecordCount)
        {
            return OperationStatus.InvalidData;
        }

        var requiredLength = countLength + ((int)count * RecordLength);
        if (source.Length < requiredLength)
        {
            return OperationStatus.NeedMoreData;
        }

        if (source.Length != requiredLength)
        {
            return OperationStatus.InvalidData;
        }

        if (destination.Length < (int)count)
        {
            return OperationStatus.DestinationTooSmall;
        }

        var offset = countLength;
        for (var index = 0; index < (int)count; index++)
        {
            var timestamp = BinaryPrimitives.ReadUInt32LittleEndian(source[offset..]);
            var addressStatus = NetworkAddressCodec.TryParse(
                source[(offset + sizeof(uint))..],
                out var address,
                out var addressLength);
            if (addressStatus != OperationStatus.Done || addressLength != NetworkAddressCodec.EncodedLength)
            {
                return OperationStatus.InvalidData;
            }

            destination[index] = new LegacyAddressRecord(timestamp, address);
            offset += RecordLength;
        }

        recordsWritten = (int)count;
        bytesConsumed = requiredLength;
        return OperationStatus.Done;
    }

    public static OperationStatus TryWrite(
        ReadOnlySpan<LegacyAddressRecord> records,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = 0;
        if (records.Length > MaximumRecordCount)
        {
            return OperationStatus.InvalidData;
        }

        Span<byte> encodedCount = stackalloc byte[sizeof(ulong) + 1];
        _ = CompactSize.Write((ulong)records.Length, encodedCount, out var countLength);
        var requiredLength = countLength + (records.Length * RecordLength);
        if (destination.Length < requiredLength)
        {
            return OperationStatus.DestinationTooSmall;
        }

        encodedCount[..countLength].CopyTo(destination);
        var offset = countLength;
        foreach (ref readonly var record in records)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(destination[offset..], record.TimestampUnixSeconds);
            _ = NetworkAddressCodec.TryWrite(
                destination[(offset + sizeof(uint))..],
                record.Address,
                out var addressLength);
            offset += sizeof(uint) + addressLength;
        }

        bytesWritten = offset;
        return OperationStatus.Done;
    }
}
