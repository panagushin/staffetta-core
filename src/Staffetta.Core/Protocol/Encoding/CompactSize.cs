using System.Buffers;
using System.Buffers.Binary;

namespace Staffetta.Core.Protocol.Encoding;

public static class CompactSize
{
    private const byte UInt16Prefix = 0xfd;
    private const byte UInt32Prefix = 0xfe;
    private const byte UInt64Prefix = 0xff;

    public static OperationStatus Read(
        ReadOnlySpan<byte> source,
        out ulong value,
        out int bytesConsumed)
    {
        value = 0;
        bytesConsumed = 0;

        if (source.IsEmpty)
        {
            return OperationStatus.NeedMoreData;
        }

        var prefix = source[0];
        if (prefix < UInt16Prefix)
        {
            value = prefix;
            bytesConsumed = 1;
            return OperationStatus.Done;
        }

        var encodedLength = prefix switch
        {
            UInt16Prefix => 3,
            UInt32Prefix => 5,
            _ => 9,
        };

        if (source.Length < encodedLength)
        {
            return OperationStatus.NeedMoreData;
        }

        value = prefix switch
        {
            UInt16Prefix => BinaryPrimitives.ReadUInt16LittleEndian(source[1..]),
            UInt32Prefix => BinaryPrimitives.ReadUInt32LittleEndian(source[1..]),
            _ => BinaryPrimitives.ReadUInt64LittleEndian(source[1..]),
        };

        var isCanonical = prefix switch
        {
            UInt16Prefix => value >= UInt16Prefix,
            UInt32Prefix => value > ushort.MaxValue,
            _ => value > uint.MaxValue,
        };

        if (!isCanonical)
        {
            value = 0;
            return OperationStatus.InvalidData;
        }

        bytesConsumed = encodedLength;
        return OperationStatus.Done;
    }

    public static OperationStatus Write(
        ulong value,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = 0;
        var encodedLength = GetEncodedLength(value);

        if (destination.Length < encodedLength)
        {
            return OperationStatus.DestinationTooSmall;
        }

        switch (encodedLength)
        {
            case 1:
                destination[0] = (byte)value;
                break;
            case 3:
                destination[0] = UInt16Prefix;
                BinaryPrimitives.WriteUInt16LittleEndian(destination[1..], (ushort)value);
                break;
            case 5:
                destination[0] = UInt32Prefix;
                BinaryPrimitives.WriteUInt32LittleEndian(destination[1..], (uint)value);
                break;
            default:
                destination[0] = UInt64Prefix;
                BinaryPrimitives.WriteUInt64LittleEndian(destination[1..], value);
                break;
        }

        bytesWritten = encodedLength;
        return OperationStatus.Done;
    }

    private static int GetEncodedLength(ulong value) => value switch
    {
        < UInt16Prefix => 1,
        <= ushort.MaxValue => 3,
        <= uint.MaxValue => 5,
        _ => 9,
    };
}
