using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Staffetta.Core.Protocol.Cryptography;

/// <summary>A copied 32-byte hash value stored in protocol wire order.</summary>
/// <remarks>
/// Wire order preserves the bytes of the SHA-256 digest. Display hexadecimal reverses those
/// bytes, as conventionally used for transaction and block identifiers. The default value is all zeroes.
/// </remarks>
public readonly struct Hash256 : IEquatable<Hash256>
{
    /// <summary>The number of bytes in a hash.</summary>
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

    /// <summary>Copies an exactly 32-byte wire-order value without reversing its bytes.</summary>
    /// <param name="wireBytes">The complete hash bytes; no reference to the storage is retained.</param>
    /// <param name="hash">The copied value on success; otherwise the default value.</param>
    /// <returns><see cref="OperationStatus.Done"/> for exactly 32 bytes; otherwise <see cref="OperationStatus.InvalidData"/>.</returns>
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

    /// <summary>Hashes the source with SHA-256 twice and preserves the final digest's byte order.</summary>
    /// <param name="source">The bytes to hash synchronously; the storage is not retained.</param>
    /// <returns>The double-SHA-256 digest in wire order.</returns>
    public static Hash256 DoubleSha256(ReadOnlySpan<byte> source)
    {
        Span<byte> firstHash = stackalloc byte[Length];
        Span<byte> secondHash = stackalloc byte[Length];
        SHA256.HashData(source, firstHash);
        SHA256.HashData(firstHash, secondHash);
        return FromWireBytes(secondHash);
    }

    /// <summary>Copies the hash in wire order, leaving the destination unchanged if it is too small.</summary>
    /// <param name="destination">Storage for at least 32 bytes; any trailing bytes are untouched.</param>
    /// <param name="bytesWritten">32 on success; otherwise zero.</param>
    /// <returns><see cref="OperationStatus.Done"/> or <see cref="OperationStatus.DestinationTooSmall"/>.</returns>
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

    /// <summary>Formats lowercase hexadecimal with bytes reversed from wire order.</summary>
    /// <returns>A 64-character display identifier.</returns>
    public string ToDisplayHex()
    {
        Span<byte> wireBytes = stackalloc byte[Length];
        WriteWireBytesTo(wireBytes);
        wireBytes.Reverse();
        return Convert.ToHexStringLower(wireBytes);
    }

    /// <inheritdoc/>
    public bool Equals(Hash256 other) =>
        _part0 == other._part0 &&
        _part1 == other._part1 &&
        _part2 == other._part2 &&
        _part3 == other._part3;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is Hash256 other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(_part0, _part1, _part2, _part3);

    /// <summary>Tests whether every hash byte is equal.</summary>
    public static bool operator ==(Hash256 left, Hash256 right) => left.Equals(right);

    /// <summary>Tests whether any hash byte differs.</summary>
    public static bool operator !=(Hash256 left, Hash256 right) => !left.Equals(right);

    internal static Hash256 FromWireBytes(ReadOnlySpan<byte> wireBytes) =>
        new(
            BinaryPrimitives.ReadUInt64LittleEndian(wireBytes),
            BinaryPrimitives.ReadUInt64LittleEndian(wireBytes[sizeof(ulong)..]),
            BinaryPrimitives.ReadUInt64LittleEndian(wireBytes[(sizeof(ulong) * 2)..]),
            BinaryPrimitives.ReadUInt64LittleEndian(wireBytes[(sizeof(ulong) * 3)..]));

    internal UInt256 ToUInt256() => new(_part0, _part1, _part2, _part3);

    internal void WriteWireBytesTo(Span<byte> destination)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(destination, _part0);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[sizeof(ulong)..], _part1);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[(sizeof(ulong) * 2)..], _part2);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[(sizeof(ulong) * 3)..], _part3);
    }
}
