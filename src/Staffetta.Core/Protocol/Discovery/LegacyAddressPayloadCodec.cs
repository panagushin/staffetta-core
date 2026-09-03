using System.Buffers;
using System.Buffers.Binary;
using Staffetta.Core.Protocol.Encoding;
using Staffetta.Core.Protocol.Handshake;

namespace Staffetta.Core.Protocol.Discovery;

/// <summary>Encodes and decodes bounded legacy addr payloads into caller-owned storage.</summary>
/// <remarks>Advertised addresses and timestamps are not checked for routability, reachability, or freshness.</remarks>
public static class LegacyAddressPayloadCodec
{
    /// <summary>The maximum number of records accepted in one legacy addr payload.</summary>
    public const int MaximumRecordCount = 1_000;
    /// <summary>The byte length of one timestamp and legacy network address.</summary>
    public const int RecordLength = sizeof(uint) + NetworkAddressCodec.EncodedLength;
    /// <summary>The maximum payload length, including the canonical record-count prefix.</summary>
    public const int MaximumPayloadLength = 3 + (MaximumRecordCount * RecordLength);

    /// <summary>Parses one exact whole payload without partial output on failure.</summary>
    /// <param name="source">The complete payload; trailing bytes are invalid.</param>
    /// <param name="destination">Storage for the declared record count; records are copied, not borrowed.</param>
    /// <param name="recordsWritten">The record count on success; otherwise zero.</param>
    /// <param name="bytesConsumed">The payload length on success; otherwise zero.</param>
    /// <returns>
    /// <see cref="OperationStatus.Done"/>, <see cref="OperationStatus.NeedMoreData"/> for truncation,
    /// <see cref="OperationStatus.DestinationTooSmall"/> for insufficient record storage, or
    /// <see cref="OperationStatus.InvalidData"/> for noncanonical or excessive counts or extra bytes.
    /// </returns>
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

    /// <summary>Writes a canonical payload, leaving the destination unchanged on failure.</summary>
    /// <param name="records">At most <see cref="MaximumRecordCount"/> records to serialize.</param>
    /// <param name="destination">Output storage; trailing bytes are untouched.</param>
    /// <param name="bytesWritten">The payload length on success; otherwise zero.</param>
    /// <returns>
    /// <see cref="OperationStatus.Done"/>, <see cref="OperationStatus.InvalidData"/> for too many records,
    /// or <see cref="OperationStatus.DestinationTooSmall"/> for insufficient storage.
    /// </returns>
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
