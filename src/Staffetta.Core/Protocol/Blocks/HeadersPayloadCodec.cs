using System.Buffers;
using Staffetta.Core.Protocol.Encoding;

namespace Staffetta.Core.Protocol.Blocks;

/// <summary>Encodes and decodes bounded headers payloads with canonical counts and zero transaction markers.</summary>
/// <remarks>Parsing checks serialization only, not proof of work, ancestry, difficulty, or chain membership.</remarks>
public static class HeadersPayloadCodec
{
    /// <summary>The maximum number of headers accepted in one payload.</summary>
    public const int MaximumHeaderCount = 2_000;

    private const int TransactionCountLength = 1;

    /// <summary>Parses an exact whole payload into caller-owned storage without partial output on failure.</summary>
    /// <param name="source">The complete payload; trailing bytes are invalid.</param>
    /// <param name="destination">Storage for the declared number of headers.</param>
    /// <param name="headersWritten">The decoded count on success; otherwise zero.</param>
    /// <returns>
    /// <see cref="OperationStatus.Done"/>, <see cref="OperationStatus.NeedMoreData"/> for truncation,
    /// <see cref="OperationStatus.DestinationTooSmall"/> for insufficient header storage, or
    /// <see cref="OperationStatus.InvalidData"/> for malformed counts, markers, or extra bytes.
    /// </returns>
    public static OperationStatus TryParse(
        ReadOnlySpan<byte> source,
        Span<BlockHeader> destination,
        out int headersWritten)
    {
        headersWritten = 0;
        var countStatus = CompactSize.Read(source, out var encodedCount, out var countLength);
        if (countStatus != OperationStatus.Done)
        {
            return countStatus;
        }

        if (encodedCount > MaximumHeaderCount)
        {
            return OperationStatus.InvalidData;
        }

        var count = (int)encodedCount;
        if (destination.Length < count)
        {
            return OperationStatus.DestinationTooSmall;
        }

        var requiredLength = checked(countLength + (count * (BlockHeaderCodec.EncodedLength + TransactionCountLength)));
        if (source.Length < requiredLength)
        {
            return OperationStatus.NeedMoreData;
        }

        if (source.Length != requiredLength)
        {
            return OperationStatus.InvalidData;
        }

        for (var index = 0; index < count; index++)
        {
            var transactionCountOffset =
                countLength +
                (index * (BlockHeaderCodec.EncodedLength + TransactionCountLength)) +
                BlockHeaderCodec.EncodedLength;
            if (source[transactionCountOffset] != 0)
            {
                return OperationStatus.InvalidData;
            }
        }

        var offset = countLength;
        for (var index = 0; index < count; index++)
        {
            var headerStatus = BlockHeaderCodec.TryParse(source[offset..], out var header, out var headerLength);
            if (headerStatus != OperationStatus.Done)
            {
                return headerStatus;
            }

            offset += headerLength;
            offset += TransactionCountLength;
            destination[index] = header;
        }

        headersWritten = count;
        return OperationStatus.Done;
    }

    /// <summary>Writes a canonical whole payload without modifying the destination on failure.</summary>
    /// <param name="headers">At most <see cref="MaximumHeaderCount"/> headers to serialize.</param>
    /// <param name="destination">Output storage; bytes after the payload are untouched.</param>
    /// <param name="bytesWritten">The payload length on success; otherwise zero.</param>
    /// <returns>
    /// <see cref="OperationStatus.Done"/>, <see cref="OperationStatus.InvalidData"/> for too many headers,
    /// or <see cref="OperationStatus.DestinationTooSmall"/> for insufficient storage.
    /// </returns>
    public static OperationStatus TryWrite(
        ReadOnlySpan<BlockHeader> headers,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = 0;
        if (headers.Length > MaximumHeaderCount)
        {
            return OperationStatus.InvalidData;
        }

        Span<byte> encodedCount = stackalloc byte[sizeof(ulong) + 1];
        var countStatus = CompactSize.Write((ulong)headers.Length, encodedCount, out var countLength);
        if (countStatus != OperationStatus.Done)
        {
            return countStatus;
        }

        var requiredLength = checked(countLength + (headers.Length * (BlockHeaderCodec.EncodedLength + TransactionCountLength)));
        if (destination.Length < requiredLength)
        {
            return OperationStatus.DestinationTooSmall;
        }

        encodedCount[..countLength].CopyTo(destination);
        var offset = countLength;
        foreach (ref readonly var header in headers)
        {
            BlockHeaderCodec.WriteUnchecked(destination[offset..], header);
            offset += BlockHeaderCodec.EncodedLength;
            destination[offset] = 0;
            offset += TransactionCountLength;
        }

        bytesWritten = requiredLength;
        return OperationStatus.Done;
    }
}
