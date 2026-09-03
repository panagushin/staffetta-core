using System.Buffers;

namespace Staffetta.Core.Protocol.Wire;

/// <summary>A copied wire-header descriptor, excluding network magic and payload bytes.</summary>
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

    /// <summary>Gets the payload command, using the inner command for extended frames.</summary>
    public MessageCommand Command { get; }

    /// <summary>Gets the declared payload length in bytes, not evidence that the payload was received.</summary>
    public ulong PayloadLength { get; }

    /// <summary>Gets the declared basic checksum, or zero for an extended header.</summary>
    public MessageChecksum PayloadChecksum { get; }

    /// <summary>Gets the basic or extended wire encoding, or Unknown for a default descriptor.</summary>
    public MessageHeaderFormat Format { get; }

    /// <summary>Gets the header byte length, or zero for an unknown format.</summary>
    public int EncodedLength => Format switch
    {
        MessageHeaderFormat.Basic => MessageHeaderCodec.BasicHeaderLength,
        MessageHeaderFormat.Extended => MessageHeaderCodec.ExtendedHeaderLength,
        _ => 0,
    };

    /// <summary>Creates an outbound basic descriptor without reading or validating its payload.</summary>
    /// <param name="command">A nonempty printable ASCII command other than extmsg; copied.</param>
    /// <param name="payloadLength">The declared payload length in bytes.</param>
    /// <param name="payloadChecksum">Exactly four checksum bytes in wire order; copied.</param>
    /// <param name="header">The descriptor on success; otherwise default.</param>
    /// <returns>Done for valid command and checksum encodings; otherwise InvalidData.</returns>
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

    /// <summary>Creates an outbound extended descriptor with a zero checksum.</summary>
    /// <param name="command">The nonempty printable ASCII inner command; copied.</param>
    /// <param name="payloadLength">A declared length greater than <see cref="uint.MaxValue"/>.</param>
    /// <param name="header">The descriptor on success; otherwise default.</param>
    /// <returns>Done for valid input; otherwise InvalidData. Smaller inbound extended frames may still be parsed.</returns>
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

    /// <summary>Tests equality of command, declared length, checksum, and format.</summary>
    public bool Equals(MessageHeader other) =>
        Command == other.Command &&
        PayloadLength == other.PayloadLength &&
        PayloadChecksum == other.PayloadChecksum &&
        Format == other.Format;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is MessageHeader other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Command, PayloadLength, PayloadChecksum, Format);

    /// <summary>Tests equality of two header descriptors.</summary>
    public static bool operator ==(MessageHeader left, MessageHeader right) => left.Equals(right);

    /// <summary>Tests inequality of two header descriptors.</summary>
    public static bool operator !=(MessageHeader left, MessageHeader right) => !left.Equals(right);
}
