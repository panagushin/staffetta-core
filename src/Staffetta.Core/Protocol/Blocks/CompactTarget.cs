using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

internal readonly struct CompactTarget
{
    private const uint MantissaMask = 0x007fffff;
    private const uint SignMask = 0x00800000;

    private CompactTarget(UInt256 value, bool isNegative, bool isOverflow)
    {
        Value = value;
        IsNegative = isNegative;
        IsOverflow = isOverflow;
    }

    internal UInt256 Value { get; }

    internal bool IsNegative { get; }

    internal bool IsOverflow { get; }

    internal static CompactTarget Decode(uint compact)
    {
        var size = (int)(compact >> 24);
        var word = compact & MantissaMask;
        UInt256 value;
        if (size <= 3)
        {
            word >>= 8 * (3 - size);
            value = UInt256.FromUInt64(word);
        }
        else
        {
            value = UInt256.FromUInt64(word).ShiftLeft(8 * (size - 3));
        }

        var isNegative = word != 0 && (compact & SignMask) != 0;
        var isOverflow = word != 0 &&
            (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
        return new CompactTarget(value, isNegative, isOverflow);
    }

    internal static uint Encode(UInt256 value, bool isNegative = false)
    {
        var size = (value.BitLength + 7) / 8;
        uint compact;
        if (size <= 3)
        {
            compact = (uint)(value.Low64 << (8 * (3 - size)));
        }
        else
        {
            compact = (uint)value.ShiftRight(8 * (size - 3)).Low64;
        }

        if ((compact & SignMask) != 0)
        {
            compact >>= 8;
            size++;
        }

        compact |= (uint)size << 24;
        if (isNegative && (compact & MantissaMask) != 0)
        {
            compact |= SignMask;
        }

        return compact;
    }
}
