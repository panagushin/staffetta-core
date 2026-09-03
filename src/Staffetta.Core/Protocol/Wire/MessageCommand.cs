using System.Buffers;
using System.Buffers.Binary;

namespace Staffetta.Core.Protocol.Wire;

/// <summary>A copied, zero-padded wire command of up to twelve printable ASCII bytes.</summary>
/// <remarks>The default value represents an empty command. Inbound parsing permits it; outbound creation does not.</remarks>
public readonly struct MessageCommand : IEquatable<MessageCommand>
{
    /// <summary>The fixed wire field width and maximum unpadded command length, in bytes.</summary>
    public const int MaximumLength = 12;

    private readonly ulong _firstEightBytes;
    private readonly uint _lastFourBytes;

    private MessageCommand(ulong firstEightBytes, uint lastFourBytes)
    {
        _firstEightBytes = firstEightBytes;
        _lastFourBytes = lastFourBytes;
    }

    /// <summary>Gets the number of command bytes before the first padding zero.</summary>
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

    /// <summary>Copies a nonempty, unpadded printable ASCII command into a value.</summary>
    /// <param name="value">One to twelve bytes in the inclusive range 0x20 through 0x7e; not retained.</param>
    /// <param name="command">The copied command on success; otherwise the default value.</param>
    /// <returns>Done for a valid command; InvalidData for an invalid length or byte.</returns>
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

    /// <summary>Copies the command without wire padding into caller-owned storage.</summary>
    /// <param name="destination">Storage for at least <see cref="Length"/> bytes.</param>
    /// <param name="bytesWritten">The command length on success; otherwise zero.</param>
    /// <returns>Done, or DestinationTooSmall without modifying the destination.</returns>
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

    /// <summary>Tests byte-for-byte equality with an unpadded command, including its length.</summary>
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

    /// <summary>Tests equality of all stored command and padding bytes.</summary>
    public bool Equals(MessageCommand other) =>
        _firstEightBytes == other._firstEightBytes && _lastFourBytes == other._lastFourBytes;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is MessageCommand other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(_firstEightBytes, _lastFourBytes);

    /// <summary>Tests equality of two wire commands.</summary>
    public static bool operator ==(MessageCommand left, MessageCommand right) => left.Equals(right);

    /// <summary>Tests inequality of two wire commands.</summary>
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
