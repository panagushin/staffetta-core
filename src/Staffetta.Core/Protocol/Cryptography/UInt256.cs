using System.Buffers.Binary;
using System.Numerics;

namespace Staffetta.Core.Protocol.Cryptography;

internal readonly struct UInt256 : IComparable<UInt256>, IEquatable<UInt256>
{
    private readonly ulong _part0;
    private readonly ulong _part1;
    private readonly ulong _part2;
    private readonly ulong _part3;

    internal UInt256(ulong part0, ulong part1, ulong part2, ulong part3)
    {
        _part0 = part0;
        _part1 = part1;
        _part2 = part2;
        _part3 = part3;
    }

    internal static UInt256 Zero => default;

    internal static UInt256 MaxValue => new(ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, ulong.MaxValue);

    internal bool IsZero => (_part0 | _part1 | _part2 | _part3) == 0;

    internal int BitLength
    {
        get
        {
            if (_part3 != 0)
            {
                return 256 - BitOperations.LeadingZeroCount(_part3);
            }

            if (_part2 != 0)
            {
                return 192 - BitOperations.LeadingZeroCount(_part2);
            }

            if (_part1 != 0)
            {
                return 128 - BitOperations.LeadingZeroCount(_part1);
            }

            return _part0 == 0 ? 0 : 64 - BitOperations.LeadingZeroCount(_part0);
        }
    }

    internal ulong Low64 => _part0;

    internal static UInt256 FromUInt64(ulong value) => new(value, 0, 0, 0);

    internal static UInt256 FromLittleEndian(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 32)
        {
            throw new ArgumentException("A UInt256 requires exactly 32 bytes.", nameof(bytes));
        }

        return new UInt256(
            BinaryPrimitives.ReadUInt64LittleEndian(bytes),
            BinaryPrimitives.ReadUInt64LittleEndian(bytes[sizeof(ulong)..]),
            BinaryPrimitives.ReadUInt64LittleEndian(bytes[(sizeof(ulong) * 2)..]),
            BinaryPrimitives.ReadUInt64LittleEndian(bytes[(sizeof(ulong) * 3)..]));
    }

    internal UInt256 ShiftLeft(int shift)
    {
        if ((uint)shift >= 256)
        {
            return Zero;
        }

        if (shift == 0)
        {
            return this;
        }

        var limbShift = shift / 64;
        var bitShift = shift % 64;
        Span<ulong> source = stackalloc ulong[4] { _part0, _part1, _part2, _part3 };
        Span<ulong> result = stackalloc ulong[4];
        result.Clear();

        for (var destination = 3; destination >= limbShift; destination--)
        {
            var sourceIndex = destination - limbShift;
            result[destination] = source[sourceIndex] << bitShift;
            if (bitShift != 0 && sourceIndex > 0)
            {
                result[destination] |= source[sourceIndex - 1] >> (64 - bitShift);
            }
        }

        return new UInt256(result[0], result[1], result[2], result[3]);
    }

    internal UInt256 ShiftRight(int shift)
    {
        if ((uint)shift >= 256)
        {
            return Zero;
        }

        if (shift == 0)
        {
            return this;
        }

        var limbShift = shift / 64;
        var bitShift = shift % 64;
        Span<ulong> source = stackalloc ulong[4] { _part0, _part1, _part2, _part3 };
        Span<ulong> result = stackalloc ulong[4];
        result.Clear();

        for (var destination = 0; destination + limbShift < 4; destination++)
        {
            var sourceIndex = destination + limbShift;
            result[destination] = source[sourceIndex] >> bitShift;
            if (bitShift != 0 && sourceIndex < 3)
            {
                result[destination] |= source[sourceIndex + 1] << (64 - bitShift);
            }
        }

        return new UInt256(result[0], result[1], result[2], result[3]);
    }

    internal UInt256 AddOne()
    {
        var part0 = _part0 + 1;
        var carry = part0 == 0 ? 1UL : 0UL;
        var part1 = _part1 + carry;
        carry = carry != 0 && part1 == 0 ? 1UL : 0UL;
        var part2 = _part2 + carry;
        carry = carry != 0 && part2 == 0 ? 1UL : 0UL;
        return new UInt256(part0, part1, part2, _part3 + carry);
    }

    internal static UInt256 Divide(UInt256 numerator, UInt256 denominator)
    {
        if (denominator.IsZero)
        {
            throw new DivideByZeroException();
        }

        var quotient = Zero;
        var remainder = Zero;
        for (var bit = 255; bit >= 0; bit--)
        {
            var carried = (remainder._part3 & 0x8000000000000000) != 0;
            remainder = remainder.ShiftLeft(1);
            if (numerator.GetBit(bit))
            {
                remainder = remainder.AddOne();
            }

            if (carried || remainder >= denominator)
            {
                remainder = remainder.Subtract(denominator);
                quotient = quotient.WithBit(bit);
            }
        }

        return quotient;
    }

    internal UInt256 OnesComplement() => new(~_part0, ~_part1, ~_part2, ~_part3);

    public int CompareTo(UInt256 other)
    {
        var comparison = _part3.CompareTo(other._part3);
        if (comparison != 0)
        {
            return comparison;
        }

        comparison = _part2.CompareTo(other._part2);
        if (comparison != 0)
        {
            return comparison;
        }

        comparison = _part1.CompareTo(other._part1);
        return comparison != 0 ? comparison : _part0.CompareTo(other._part0);
    }

    public bool Equals(UInt256 other) =>
        _part0 == other._part0 &&
        _part1 == other._part1 &&
        _part2 == other._part2 &&
        _part3 == other._part3;

    public override bool Equals(object? obj) => obj is UInt256 other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(_part0, _part1, _part2, _part3);

    public static bool operator ==(UInt256 left, UInt256 right) => left.Equals(right);

    public static bool operator !=(UInt256 left, UInt256 right) => !left.Equals(right);

    public static bool operator <(UInt256 left, UInt256 right) => left.CompareTo(right) < 0;

    public static bool operator <=(UInt256 left, UInt256 right) => left.CompareTo(right) <= 0;

    public static bool operator >(UInt256 left, UInt256 right) => left.CompareTo(right) > 0;

    public static bool operator >=(UInt256 left, UInt256 right) => left.CompareTo(right) >= 0;

    private bool GetBit(int bit)
    {
        var limb = bit / 64;
        var offset = bit % 64;
        return limb switch
        {
            0 => (_part0 & (1UL << offset)) != 0,
            1 => (_part1 & (1UL << offset)) != 0,
            2 => (_part2 & (1UL << offset)) != 0,
            _ => (_part3 & (1UL << offset)) != 0,
        };
    }

    private UInt256 WithBit(int bit)
    {
        var value = 1UL << (bit % 64);
        return (bit / 64) switch
        {
            0 => new UInt256(_part0 | value, _part1, _part2, _part3),
            1 => new UInt256(_part0, _part1 | value, _part2, _part3),
            2 => new UInt256(_part0, _part1, _part2 | value, _part3),
            _ => new UInt256(_part0, _part1, _part2, _part3 | value),
        };
    }

    private UInt256 Subtract(UInt256 other)
    {
        var part0 = _part0 - other._part0;
        var borrow = _part0 < other._part0 ? 1UL : 0UL;

        var part1Subtrahend = other._part1 + borrow;
        var part1Carry = part1Subtrahend < other._part1;
        var part1 = _part1 - part1Subtrahend;
        borrow = part1Carry || _part1 < part1Subtrahend ? 1UL : 0UL;

        var part2Subtrahend = other._part2 + borrow;
        var part2Carry = part2Subtrahend < other._part2;
        var part2 = _part2 - part2Subtrahend;
        borrow = part2Carry || _part2 < part2Subtrahend ? 1UL : 0UL;

        return new UInt256(part0, part1, part2, _part3 - other._part3 - borrow);
    }
}
