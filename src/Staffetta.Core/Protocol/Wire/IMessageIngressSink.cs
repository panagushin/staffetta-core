namespace Staffetta.Core.Protocol.Wire;

public interface IMessageIngressSink
{
    void OnMessageStarted(in MessageHeader header);

    /// <summary>
    /// Receives payload bytes that are provisional within the framing layer.
    /// </summary>
    /// <remarks>
    /// The span is valid only for the duration of this synchronous call. Frame validation does not
    /// imply structural or business validation, so downstream effects must remain staged until the
    /// relevant higher-level validators accept them. Call <see cref="MessageIngressStateMachine.CompleteEndOfInput"/>
    /// before disposal to receive an abort callback for a truncated frame; disposal alone is abrupt
    /// cancellation and does not invoke the sink.
    /// </remarks>
    void OnProvisionalPayload(ReadOnlySpan<byte> payload);

    void OnMessageCompleted(MessageIngressCompletion completion);
}
