namespace Staffetta.Core.Protocol.Wire;

/// <summary>
/// Decides whether a fully parsed wire-message header may enter payload processing.
/// </summary>
/// <remarks>
/// The policy runs before payload-validator creation and before the ingress sink is notified.
/// Implementations must not re-enter the ingress instance that invokes them.
/// </remarks>
public interface IMessageIngressAdmissionPolicy
{
    bool IsAdmitted(in MessageHeader header);
}
