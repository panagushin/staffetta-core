namespace Staffetta.Core.Protocol.Wire;

public interface IMessageIngressSink
{
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
    System.Buffers.OperationStatus OnProvisionalPayload(ReadOnlySpan<byte> payload);

    void OnMessageCompleted(in MessageIngressResult result);
}
