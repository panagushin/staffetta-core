namespace Staffetta.Core.Protocol.Transactions;

/// <summary>Receives borrowed, provisional raw transaction payload chunks without wire headers.</summary>
/// <remarks>
/// Chunk boundaries have no meaning. Copy or consume each span before returning; do not re-enter
/// the session. Bytes may precede structural rejection or checksum failure and must not be published
/// until the corresponding transaction sink commits. Storage, backpressure and recovery belong
/// to the caller, which must bound the amount passed to each session consume call.
/// </remarks>
public interface ITransactionPayloadSink
{
    /// <summary>Consumes the next provisional transaction bytes; no input span may be retained.</summary>
    void OnTransactionPayload(ReadOnlySpan<byte> bytes);
}
