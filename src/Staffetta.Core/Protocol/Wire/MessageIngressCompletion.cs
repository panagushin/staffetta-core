namespace Staffetta.Core.Protocol.Wire;

/// <summary>Describes whether a started frame completed framing validation or was aborted.</summary>
public enum MessageIngressCompletion
{
    /// <summary>
    /// The basic checksum matched, or the declared extended payload length was consumed.
    /// </summary>
    FrameValidated,

    /// <summary>The frame failed validation, was rejected by the payload sink, or ended before all declared payload bytes arrived.</summary>
    FrameAborted,
}
