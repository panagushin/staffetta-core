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
    /// <summary>Decides whether to process a parsed header before payload allocation or sink notification.</summary>
    /// <param name="header">Declared command, length, checksum, and format; the payload is not yet validated.</param>
    /// <returns>True to admit the frame; false to permanently fault ingress at its header boundary.</returns>
    bool IsAdmitted(in MessageHeader header);
}
