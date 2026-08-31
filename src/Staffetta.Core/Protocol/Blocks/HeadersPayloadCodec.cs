using System.Buffers;
using Staffetta.Core.Protocol.Encoding;

namespace Staffetta.Core.Protocol.Blocks;

public static class HeadersPayloadCodec
{
    public const int MaximumHeaderCount = 2_000;

    private const int TransactionCountLength = 1;

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
