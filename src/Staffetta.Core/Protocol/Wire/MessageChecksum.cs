using System.Buffers;
using System.Buffers.Binary;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Wire;

/// <summary>The first four digest bytes of a wire payload's double-SHA-256 hash.</summary>
public readonly struct MessageChecksum : IEquatable<MessageChecksum>
{
    /// <summary>The checksum length in wire bytes.</summary>
    public const int Length = 4;

    private readonly uint _littleEndianValue;

    private MessageChecksum(uint littleEndianValue)
    {
        _littleEndianValue = littleEndianValue;
    }

    /// <summary>Gets checksum byte 0 in wire order.</summary>
    public byte Byte0 => (byte)_littleEndianValue;

    /// <summary>Gets checksum byte 1 in wire order.</summary>
    public byte Byte1 => (byte)(_littleEndianValue >> 8);

    /// <summary>Gets checksum byte 2 in wire order.</summary>
    public byte Byte2 => (byte)(_littleEndianValue >> 16);

    /// <summary>Gets checksum byte 3 in wire order.</summary>
    public byte Byte3 => (byte)(_littleEndianValue >> 24);

    /// <summary>Gets the all-zero checksum required by extended headers.</summary>
    public static MessageChecksum Zero => default;

    /// <summary>Computes a checksum over the entire supplied payload without retaining its bytes.</summary>
    public static MessageChecksum Compute(ReadOnlySpan<byte> payload)
    {
        var hash = Hash256.DoubleSha256(payload);
        Span<byte> wireBytes = stackalloc byte[Hash256.Length];
        hash.WriteWireBytesTo(wireBytes);
        return FromBytes(wireBytes);
    }

    /// <summary>Copies exactly four checksum bytes in wire order.</summary>
    /// <param name="value">The caller-owned checksum bytes; not retained.</param>
    /// <param name="checksum">The copied checksum on success; otherwise zero.</param>
    /// <returns>Done for exactly four bytes; otherwise InvalidData.</returns>
    public static OperationStatus TryCreate(ReadOnlySpan<byte> value, out MessageChecksum checksum)
    {
        checksum = default;

        if (value.Length != Length)
        {
            return OperationStatus.InvalidData;
        }

        checksum = FromBytes(value);
        return OperationStatus.Done;
    }

    /// <summary>Copies the four checksum bytes into caller-owned storage in wire order.</summary>
    /// <param name="destination">Storage for at least four bytes.</param>
    /// <param name="bytesWritten">Four on success; otherwise zero.</param>
    /// <returns>Done, or DestinationTooSmall without modifying the destination.</returns>
    public OperationStatus TryCopyTo(Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;

        if (destination.Length < Length)
        {
            return OperationStatus.DestinationTooSmall;
        }

        WriteTo(destination);
        bytesWritten = Length;
        return OperationStatus.Done;
    }

    /// <summary>Tests equality of all four checksum bytes.</summary>
    public bool Equals(MessageChecksum other) => _littleEndianValue == other._littleEndianValue;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is MessageChecksum other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => _littleEndianValue.GetHashCode();

    /// <summary>Tests equality of two checksums.</summary>
    public static bool operator ==(MessageChecksum left, MessageChecksum right) => left.Equals(right);

    /// <summary>Tests inequality of two checksums.</summary>
    public static bool operator !=(MessageChecksum left, MessageChecksum right) => !left.Equals(right);

    internal static MessageChecksum FromBytes(ReadOnlySpan<byte> value) =>
        new(BinaryPrimitives.ReadUInt32LittleEndian(value));

    internal void WriteTo(Span<byte> destination) =>
        BinaryPrimitives.WriteUInt32LittleEndian(destination, _littleEndianValue);
}
