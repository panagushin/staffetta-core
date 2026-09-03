namespace Staffetta.Core.Protocol.Wire;

/// <summary>
/// Selects extended wire messages whose payload needs a full double-SHA-256 digest.
/// </summary>
/// <remarks>
/// Basic messages are always hashed to validate their checksum. Implementations must not re-enter
/// the ingress instance that invokes them.
/// </remarks>
public interface IMessageIngressPayloadHashPolicy
{
    /// <summary>Selects full-payload hashing for an admitted extended frame.</summary>
    /// <param name="header">The admitted extended header; payload bytes have not yet been processed.</param>
    /// <returns>True to expose a digest after frame completion; false to perform length-only framing validation.</returns>
    /// <remarks>Called once per admitted extended frame, never for basic frames. The computed digest is not compared against a peer-supplied extended checksum.</remarks>
    bool ShouldComputeDoubleSha256(in MessageHeader header);
}
