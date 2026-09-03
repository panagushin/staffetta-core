using System.Buffers;
using System.Buffers.Binary;

namespace Staffetta.Core.Protocol.Encoding;

/// <summary>Reads and writes canonical Bitcoin CompactSize unsigned integers.</summary>
public static class CompactSize
{
    private const byte UInt16Prefix = 0xfd;
    private const byte UInt32Prefix = 0xfe;
    private const byte UInt64Prefix = 0xff;

    /// <summary>Reads one minimally encoded integer, leaving trailing bytes unconsumed.</summary>
    /// <param name="source">Bytes beginning at the integer's prefix.</param>
    /// <param name="value">The decoded value on success; otherwise zero.</param>
    /// <param name="bytesConsumed">The encoded length on success; otherwise zero.</param>
    /// <returns>
    /// <see cref="OperationStatus.Done"/>, <see cref="OperationStatus.NeedMoreData"/> for an incomplete
    /// encoding, or <see cref="OperationStatus.InvalidData"/> for a nonminimal encoding.
    /// </returns>
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

    /// <summary>Writes the shortest encoding, without changing an undersized destination.</summary>
    /// <param name="value">The unsigned value to encode.</param>
    /// <param name="destination">Storage for the 1, 3, 5, or 9 encoded bytes; trailing bytes are untouched.</param>
    /// <param name="bytesWritten">The encoded length on success; otherwise zero.</param>
    /// <returns><see cref="OperationStatus.Done"/> or <see cref="OperationStatus.DestinationTooSmall"/>.</returns>
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
