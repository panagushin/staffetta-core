using System.Buffers;
using System.Buffers.Binary;

namespace Staffetta.Core.Protocol.Wire;

public static class MessageHeaderCodec
{
    public const int NetworkMagicLength = 4;
    public const int BasicHeaderLength = 24;
    public const int ExtendedHeaderLength = 44;

    private const int CommandOffset = NetworkMagicLength;
    private const int BasicPayloadLengthOffset = CommandOffset + MessageCommand.MaximumLength;
    private const int ChecksumOffset = BasicPayloadLengthOffset + sizeof(uint);
    private const int ExtendedCommandOffset = BasicHeaderLength;
    private const int ExtendedPayloadLengthOffset = ExtendedCommandOffset + MessageCommand.MaximumLength;

    public static ReadOnlySpan<byte> ExtendedCommand => "extmsg"u8;

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
        if (extendedPayloadLength <= uint.MaxValue ||
            extendedPayloadLength > maximumPayloadLength)
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
            MessageHeaderFormat.Basic when header.PayloadLength <= uint.MaxValue &&
                !header.Command.Equals(ExtendedCommand) => BasicHeaderLength,
            MessageHeaderFormat.Extended when header.PayloadLength > uint.MaxValue &&
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
