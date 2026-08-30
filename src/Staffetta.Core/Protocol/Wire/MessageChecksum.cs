using System.Buffers;
using System.Buffers.Binary;

namespace Staffetta.Core.Protocol.Wire;

public readonly struct MessageChecksum : IEquatable<MessageChecksum>
{
    public const int Length = 4;

    private readonly uint _littleEndianValue;

    private MessageChecksum(uint littleEndianValue)
    {
        _littleEndianValue = littleEndianValue;
    }

    public byte Byte0 => (byte)_littleEndianValue;

    public byte Byte1 => (byte)(_littleEndianValue >> 8);

    public byte Byte2 => (byte)(_littleEndianValue >> 16);

    public byte Byte3 => (byte)(_littleEndianValue >> 24);

    public static MessageChecksum Zero => default;

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

    public bool Equals(MessageChecksum other) => _littleEndianValue == other._littleEndianValue;

    public override bool Equals(object? obj) => obj is MessageChecksum other && Equals(other);

    public override int GetHashCode() => _littleEndianValue.GetHashCode();

    public static bool operator ==(MessageChecksum left, MessageChecksum right) => left.Equals(right);

    public static bool operator !=(MessageChecksum left, MessageChecksum right) => !left.Equals(right);

    internal static MessageChecksum FromBytes(ReadOnlySpan<byte> value) =>
        new(BinaryPrimitives.ReadUInt32LittleEndian(value));

    internal void WriteTo(Span<byte> destination) =>
        BinaryPrimitives.WriteUInt32LittleEndian(destination, _littleEndianValue);
}
