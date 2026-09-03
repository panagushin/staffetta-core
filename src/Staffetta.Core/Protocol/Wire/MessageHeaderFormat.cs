namespace Staffetta.Core.Protocol.Wire;

/// <summary>Identifies the header encoding of a wire message.</summary>
public enum MessageHeaderFormat
{
    /// <summary>No recognized header encoding, including a default descriptor.</summary>
    Unknown = 0,
    /// <summary>A 24-byte header with a 32-bit payload length and four-byte checksum.</summary>
    Basic = 1,
    /// <summary>A 44-byte extmsg header with an inner command, 64-bit length, and zero checksum.</summary>
    Extended = 2,
}
