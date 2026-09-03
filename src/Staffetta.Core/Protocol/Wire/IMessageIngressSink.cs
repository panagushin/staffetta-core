namespace Staffetta.Core.Protocol.Wire;

/// <summary>Receives synchronous frame lifecycle notifications and provisional payload slices.</summary>
/// <remarks>Callbacks must not re-enter their ingress instance. Exceptions permanently fault ingress and are propagated without replaying the callback.</remarks>
public interface IMessageIngressSink
{
    /// <summary>Begins staging one parsed and admitted frame before any payload bytes are delivered.</summary>
    /// <param name="header">The declared frame metadata, not evidence of payload validation.</param>
    void OnMessageStarted(in MessageHeader header);

    /// <summary>
    /// Receives payload bytes that are provisional within the framing layer.
    /// </summary>
    /// <remarks>
    /// The span is valid only for the duration of this synchronous call. Return
    /// <see cref="System.Buffers.OperationStatus.Done"/> only after accepting the entire span, or
    /// <see cref="System.Buffers.OperationStatus.InvalidData"/> to reject the frame. Partial
    /// consumption and payload backpressure are not supported; any other status rejects the frame
    /// as a sink-contract failure. Frame validation does not imply structural or business
    /// validation, so downstream effects must remain staged until the relevant higher-level
    /// validators accept them. Call <see cref="MessageIngressStateMachine.CompleteEndOfInput"/>
    /// before disposal to receive an abort callback for a truncated frame; disposal alone is abrupt
    /// cancellation and does not invoke the sink.
    /// </remarks>
    /// <param name="payload">The entire provisional slice to accept or reject; its backing buffer must not be retained.</param>
    /// <returns>Done after accepting the whole slice, or InvalidData to reject the frame.</returns>
    System.Buffers.OperationStatus OnProvisionalPayload(ReadOnlySpan<byte> payload);

    /// <summary>Reports successful framing validation or an explicit abort of a started frame.</summary>
    /// <param name="result">The terminal framing result and optional validated digest.</param>
    /// <remarks>Discard staged effects on abort. Successful framing still requires command-specific validation before publishing effects. Abrupt disposal and callback exceptions do not guarantee this notification.</remarks>
    void OnMessageCompleted(in MessageIngressResult result);
}
