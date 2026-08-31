using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Staffetta.Core.Protocol.Cryptography;

public readonly struct Hash256 : IEquatable<Hash256>
{
    public const int Length = 32;

    private readonly ulong _part0;
    private readonly ulong _part1;
    private readonly ulong _part2;
    private readonly ulong _part3;

    private Hash256(ulong part0, ulong part1, ulong part2, ulong part3)
    {
        _part0 = part0;
        _part1 = part1;
        _part2 = part2;
        _part3 = part3;
    }

    public static OperationStatus TryCreate(ReadOnlySpan<byte> wireBytes, out Hash256 hash)
    {
        hash = default;
        if (wireBytes.Length != Length)
        {
            return OperationStatus.InvalidData;
        }

        hash = FromWireBytes(wireBytes);
        return OperationStatus.Done;
    }

    public static Hash256 DoubleSha256(ReadOnlySpan<byte> source)
    {
        Span<byte> firstHash = stackalloc byte[Length];
        Span<byte> secondHash = stackalloc byte[Length];
        SHA256.HashData(source, firstHash);
        SHA256.HashData(firstHash, secondHash);
        return FromWireBytes(secondHash);
    }

    public OperationStatus TryCopyWireBytesTo(Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        if (destination.Length < Length)
        {
            return OperationStatus.DestinationTooSmall;
        }

        WriteWireBytesTo(destination);
        bytesWritten = Length;
        return OperationStatus.Done;
    }

    public string ToDisplayHex()
    {
        Span<byte> wireBytes = stackalloc byte[Length];
        WriteWireBytesTo(wireBytes);
        wireBytes.Reverse();
        return Convert.ToHexStringLower(wireBytes);
    }

    public bool Equals(Hash256 other) =>
        _part0 == other._part0 &&
        _part1 == other._part1 &&
        _part2 == other._part2 &&
        _part3 == other._part3;

    public override bool Equals(object? obj) => obj is Hash256 other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(_part0, _part1, _part2, _part3);

    public static bool operator ==(Hash256 left, Hash256 right) => left.Equals(right);

    public static bool operator !=(Hash256 left, Hash256 right) => !left.Equals(right);

    internal static Hash256 FromWireBytes(ReadOnlySpan<byte> wireBytes) =>
        new(
            BinaryPrimitives.ReadUInt64LittleEndian(wireBytes),
            BinaryPrimitives.ReadUInt64LittleEndian(wireBytes[sizeof(ulong)..]),
            BinaryPrimitives.ReadUInt64LittleEndian(wireBytes[(sizeof(ulong) * 2)..]),
            BinaryPrimitives.ReadUInt64LittleEndian(wireBytes[(sizeof(ulong) * 3)..]));

    internal void WriteWireBytesTo(Span<byte> destination)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(destination, _part0);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[sizeof(ulong)..], _part1);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[(sizeof(ulong) * 2)..], _part2);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[(sizeof(ulong) * 3)..], _part3);
    }
}
