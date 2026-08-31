namespace Staffetta.Core.Protocol.Wire;

public enum MessageIngressCompletion
{
    /// <summary>
    /// The basic checksum matched, or the declared extended payload length was consumed.
    /// </summary>
    FrameValidated,

    FrameAborted,
}
