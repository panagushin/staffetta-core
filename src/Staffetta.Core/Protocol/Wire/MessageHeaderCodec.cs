using System.Buffers;
using System.Buffers.Binary;

namespace Staffetta.Core.Protocol.Wire;

/// <summary>Parses and writes basic and extended headers without retaining caller buffers.</summary>
public static class MessageHeaderCodec
{
    /// <summary>The number of network-magic bytes at the beginning of either header format.</summary>
    public const int NetworkMagicLength = 4;
    /// <summary>The encoded basic header length in bytes.</summary>
    public const int BasicHeaderLength = 24;
    /// <summary>The encoded extended header length in bytes, including its outer header.</summary>
    public const int ExtendedHeaderLength = 44;

    private const int CommandOffset = NetworkMagicLength;
    private const int BasicPayloadLengthOffset = CommandOffset + MessageCommand.MaximumLength;
    private const int ChecksumOffset = BasicPayloadLengthOffset + sizeof(uint);
    private const int ExtendedCommandOffset = BasicHeaderLength;
    private const int ExtendedPayloadLengthOffset = ExtendedCommandOffset + MessageCommand.MaximumLength;

    /// <summary>Gets the unpadded outer command that marks an extended header.</summary>
    public static ReadOnlySpan<byte> ExtendedCommand => "extmsg"u8;

    /// <summary>Parses one header prefix and checks network magic, padding, sentinel fields, and the caller's length bound.</summary>
    /// <param name="source">Caller-owned bytes starting at a header; payload bytes are not examined or retained.</param>
    /// <param name="expectedNetworkMagic">Exactly four expected network-magic bytes.</param>
    /// <param name="maximumPayloadLength">The inclusive accepted payload-length bound.</param>
    /// <param name="header">A copied descriptor on success; otherwise default.</param>
    /// <param name="bytesConsumed">The header length on success; otherwise zero.</param>
    /// <returns>Done, NeedMoreData for an incomplete header, or InvalidData for a rejected header or magic argument.</returns>
    /// <remarks>Inbound compatibility permits empty commands and extended lengths at or below the basic limit. Successful parsing does not validate a payload or guarantee that the descriptor is valid for outbound writing.</remarks>
    public static OperationStatus TryParse(
        ReadOnlySpan<byte> source,
        ReadOnlySpan<byte> expectedNetworkMagic,
        ulong maximumPayloadLength,
        out MessageHeader header,
        out int bytesConsumed)
    {
        header = default;
        bytesConsumed = 0;

        if (expectedNetworkMagic.Length != NetworkMagicLength)
        {
            return OperationStatus.InvalidData;
        }

        if (source.Length < BasicHeaderLength)
        {
            return OperationStatus.NeedMoreData;
        }

        if (!source[..NetworkMagicLength].SequenceEqual(expectedNetworkMagic) ||
            MessageCommand.TryReadPadded(
                source.Slice(CommandOffset, MessageCommand.MaximumLength),
                out var outerCommand) != OperationStatus.Done)
        {
            return OperationStatus.InvalidData;
        }

        var basicPayloadLength = BinaryPrimitives.ReadUInt32LittleEndian(
            source.Slice(BasicPayloadLengthOffset, sizeof(uint)));
        var checksum = MessageChecksum.FromBytes(source.Slice(ChecksumOffset, MessageChecksum.Length));

        if (!outerCommand.Equals(ExtendedCommand))
        {
            if (basicPayloadLength > maximumPayloadLength)
            {
                return OperationStatus.InvalidData;
            }

            header = new MessageHeader(
                outerCommand,
                basicPayloadLength,
                checksum,
                MessageHeaderFormat.Basic);
            bytesConsumed = BasicHeaderLength;
            return OperationStatus.Done;
        }

        if (basicPayloadLength != uint.MaxValue || checksum != MessageChecksum.Zero)
        {
            return OperationStatus.InvalidData;
        }

        if (source.Length < ExtendedHeaderLength)
        {
            return OperationStatus.NeedMoreData;
        }

        if (MessageCommand.TryReadPadded(
                source.Slice(ExtendedCommandOffset, MessageCommand.MaximumLength),
                out var extendedCommand) != OperationStatus.Done)
        {
            return OperationStatus.InvalidData;
        }

        var extendedPayloadLength = BinaryPrimitives.ReadUInt64LittleEndian(
            source.Slice(ExtendedPayloadLengthOffset, sizeof(ulong)));
        if (extendedPayloadLength > maximumPayloadLength)
        {
            return OperationStatus.InvalidData;
        }

        header = new MessageHeader(
            extendedCommand,
            extendedPayloadLength,
            MessageChecksum.Zero,
            MessageHeaderFormat.Extended);
        bytesConsumed = ExtendedHeaderLength;
        return OperationStatus.Done;
    }

    /// <summary>Writes one outbound header after validating the descriptor and destination capacity.</summary>
    /// <param name="destination">Caller-owned storage for the encoded header.</param>
    /// <param name="networkMagic">Exactly four network-magic bytes; not retained.</param>
    /// <param name="header">A basic or extended outbound descriptor; no payload is read.</param>
    /// <param name="maximumPayloadLength">The inclusive permitted payload-length bound.</param>
    /// <param name="bytesWritten">The encoded header length on success; otherwise zero.</param>
    /// <returns>Done, InvalidData for invalid arguments, or DestinationTooSmall. Non-success leaves the destination unchanged.</returns>
    /// <remarks>Commands must be nonempty. Basic headers cannot use extmsg; extended lengths must exceed the basic 32-bit limit and carry a zero checksum.</remarks>
    public static OperationStatus TryWrite(
        Span<byte> destination,
        ReadOnlySpan<byte> networkMagic,
        in MessageHeader header,
        ulong maximumPayloadLength,
        out int bytesWritten)
    {
        bytesWritten = 0;

        if (networkMagic.Length != NetworkMagicLength ||
            header.PayloadLength > maximumPayloadLength)
        {
            return OperationStatus.InvalidData;
        }

        var requiredLength = header.Format switch
        {
            MessageHeaderFormat.Basic when header.Command.Length > 0 &&
                header.PayloadLength <= uint.MaxValue &&
                !header.Command.Equals(ExtendedCommand) => BasicHeaderLength,
            MessageHeaderFormat.Extended when header.Command.Length > 0 &&
                header.PayloadLength > uint.MaxValue &&
                header.PayloadChecksum == MessageChecksum.Zero => ExtendedHeaderLength,
            _ => 0,
        };

        if (requiredLength == 0)
        {
            return OperationStatus.InvalidData;
        }

        if (destination.Length < requiredLength)
        {
            return OperationStatus.DestinationTooSmall;
        }

        networkMagic.CopyTo(destination);

        if (header.Format == MessageHeaderFormat.Basic)
        {
            header.Command.WritePaddedTo(destination.Slice(CommandOffset, MessageCommand.MaximumLength));
            BinaryPrimitives.WriteUInt32LittleEndian(
                destination.Slice(BasicPayloadLengthOffset, sizeof(uint)),
                (uint)header.PayloadLength);
            header.PayloadChecksum.WriteTo(destination.Slice(ChecksumOffset, MessageChecksum.Length));
        }
        else
        {
            destination.Slice(CommandOffset, MessageCommand.MaximumLength).Clear();
            ExtendedCommand.CopyTo(destination[CommandOffset..]);
            BinaryPrimitives.WriteUInt32LittleEndian(
                destination.Slice(BasicPayloadLengthOffset, sizeof(uint)),
                uint.MaxValue);
            destination.Slice(ChecksumOffset, MessageChecksum.Length).Clear();
            header.Command.WritePaddedTo(destination.Slice(ExtendedCommandOffset, MessageCommand.MaximumLength));
            BinaryPrimitives.WriteUInt64LittleEndian(
                destination.Slice(ExtendedPayloadLengthOffset, sizeof(ulong)),
                header.PayloadLength);
        }

        bytesWritten = requiredLength;
        return OperationStatus.Done;
    }
}
