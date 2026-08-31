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
    bool ShouldComputeDoubleSha256(in MessageHeader header);
}
