using System.Buffers;
using System.Buffers.Binary;

namespace Staffetta.Core.Protocol.Wire;

public readonly struct MessageCommand : IEquatable<MessageCommand>
{
    public const int MaximumLength = 12;

    private readonly ulong _firstEightBytes;
    private readonly uint _lastFourBytes;

    private MessageCommand(ulong firstEightBytes, uint lastFourBytes)
    {
        _firstEightBytes = firstEightBytes;
        _lastFourBytes = lastFourBytes;
    }

    public int Length
    {
        get
        {
            for (var index = 0; index < MaximumLength; index++)
            {
                if (GetByte(index) == 0)
                {
                    return index;
                }
            }

            return MaximumLength;
        }
    }

    public static OperationStatus TryCreate(ReadOnlySpan<byte> value, out MessageCommand command)
    {
        command = default;

        if (value.IsEmpty ||
            value.Length > MaximumLength ||
            !ContainsOnlyPrintableAscii(value))
        {
            return OperationStatus.InvalidData;
        }

        Span<byte> paddedCommand = stackalloc byte[MaximumLength];
        paddedCommand.Clear();
        value.CopyTo(paddedCommand);
        command = FromPaddedBytes(paddedCommand);
        return OperationStatus.Done;
    }

    public OperationStatus TryCopyTo(Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        var length = Length;

        if (destination.Length < length)
        {
            return OperationStatus.DestinationTooSmall;
        }

        for (var index = 0; index < length; index++)
        {
            destination[index] = GetByte(index);
        }

        bytesWritten = length;
        return OperationStatus.Done;
    }

    public bool Equals(ReadOnlySpan<byte> value)
    {
        if (value.Length != Length)
        {
            return false;
        }

        for (var index = 0; index < value.Length; index++)
        {
            if (value[index] != GetByte(index))
            {
                return false;
            }
        }

        return true;
    }

    public bool Equals(MessageCommand other) =>
        _firstEightBytes == other._firstEightBytes && _lastFourBytes == other._lastFourBytes;

    public override bool Equals(object? obj) => obj is MessageCommand other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(_firstEightBytes, _lastFourBytes);

    public static bool operator ==(MessageCommand left, MessageCommand right) => left.Equals(right);

    public static bool operator !=(MessageCommand left, MessageCommand right) => !left.Equals(right);

    internal static OperationStatus TryReadPadded(ReadOnlySpan<byte> source, out MessageCommand command)
    {
        command = default;

        if (source.Length < MaximumLength)
        {
            return OperationStatus.NeedMoreData;
        }

        var paddingStarted = false;
        for (var index = 0; index < MaximumLength; index++)
        {
            var value = source[index];
            if (value == 0)
            {
                paddingStarted = true;
            }
            else if (paddingStarted || !IsPrintableAscii(value))
            {
                return OperationStatus.InvalidData;
            }
        }

        command = FromPaddedBytes(source);
        return OperationStatus.Done;
    }

    internal void WritePaddedTo(Span<byte> destination)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(destination, _firstEightBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[sizeof(ulong)..], _lastFourBytes);
    }

    private static MessageCommand FromPaddedBytes(ReadOnlySpan<byte> source) =>
        new(
            BinaryPrimitives.ReadUInt64LittleEndian(source),
            BinaryPrimitives.ReadUInt32LittleEndian(source[sizeof(ulong)..]));

    private static bool ContainsOnlyPrintableAscii(ReadOnlySpan<byte> value)
    {
        foreach (var character in value)
        {
            if (!IsPrintableAscii(character))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsPrintableAscii(byte value) => value is >= 0x20 and <= 0x7e;

    private byte GetByte(int index) =>
        index < sizeof(ulong)
            ? (byte)(_firstEightBytes >> (index * 8))
            : (byte)(_lastFourBytes >> ((index - sizeof(ulong)) * 8));
}
