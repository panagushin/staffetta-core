using System.Buffers;

namespace Staffetta.Core.Protocol.Wire;

public readonly struct MessageHeader : IEquatable<MessageHeader>
{
    internal MessageHeader(
        MessageCommand command,
        ulong payloadLength,
        MessageChecksum payloadChecksum,
        MessageHeaderFormat format)
    {
        Command = command;
        PayloadLength = payloadLength;
        PayloadChecksum = payloadChecksum;
        Format = format;
    }

    public MessageCommand Command { get; }

    public ulong PayloadLength { get; }

    public MessageChecksum PayloadChecksum { get; }

    public MessageHeaderFormat Format { get; }

    public int EncodedLength => Format switch
    {
        MessageHeaderFormat.Basic => MessageHeaderCodec.BasicHeaderLength,
        MessageHeaderFormat.Extended => MessageHeaderCodec.ExtendedHeaderLength,
        _ => 0,
    };

    public static OperationStatus TryCreateBasic(
        ReadOnlySpan<byte> command,
        uint payloadLength,
        ReadOnlySpan<byte> payloadChecksum,
        out MessageHeader header)
    {
        header = default;
        if (MessageCommand.TryCreate(command, out var parsedCommand) != OperationStatus.Done ||
            parsedCommand.Equals(MessageHeaderCodec.ExtendedCommand))
        {
            return OperationStatus.InvalidData;
        }

        if (MessageChecksum.TryCreate(payloadChecksum, out var parsedChecksum) != OperationStatus.Done)
        {
            return OperationStatus.InvalidData;
        }

        header = new MessageHeader(parsedCommand, payloadLength, parsedChecksum, MessageHeaderFormat.Basic);
        return OperationStatus.Done;
    }

    public static OperationStatus TryCreateExtended(
        ReadOnlySpan<byte> command,
        ulong payloadLength,
        out MessageHeader header)
    {
        header = default;
        if (payloadLength <= uint.MaxValue ||
            MessageCommand.TryCreate(command, out var parsedCommand) != OperationStatus.Done)
        {
            return OperationStatus.InvalidData;
        }

        header = new MessageHeader(parsedCommand, payloadLength, MessageChecksum.Zero, MessageHeaderFormat.Extended);
        return OperationStatus.Done;
    }

    public bool Equals(MessageHeader other) =>
        Command == other.Command &&
        PayloadLength == other.PayloadLength &&
        PayloadChecksum == other.PayloadChecksum &&
        Format == other.Format;

    public override bool Equals(object? obj) => obj is MessageHeader other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(Command, PayloadLength, PayloadChecksum, Format);

    public static bool operator ==(MessageHeader left, MessageHeader right) => left.Equals(right);

    public static bool operator !=(MessageHeader left, MessageHeader right) => !left.Equals(right);
}
