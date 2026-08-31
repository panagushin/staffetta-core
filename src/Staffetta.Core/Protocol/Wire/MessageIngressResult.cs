using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Wire;

/// <summary>Describes the validated or aborted terminal state of one wire frame.</summary>
public readonly struct MessageIngressResult
{
    internal MessageIngressResult(
        MessageIngressCompletion completion,
        Hash256? payloadDoubleSha256)
    {
        Completion = completion;
        PayloadDoubleSha256 = payloadDoubleSha256;
    }

    public MessageIngressCompletion Completion { get; }

    /// <summary>
    /// Gets the full validated payload digest for every basic frame and for an opted-in extended
    /// frame; otherwise, <see langword="null"/>.
    /// </summary>
    public Hash256? PayloadDoubleSha256 { get; }
}
