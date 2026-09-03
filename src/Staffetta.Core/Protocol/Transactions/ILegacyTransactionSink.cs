namespace Staffetta.Core.Protocol.Transactions;

/// <summary>
/// Receives provisional legacy-transaction structure and borrowed script chunks.
/// </summary>
/// <remarks>
/// Implementations must not publish provisional effects before <see cref="OnTransactionCommitted"/>.
/// Script spans are valid only for the duration of their callback. A sink callback must not
/// re-enter the parser that invoked it. Callbacks run synchronously in serialized field order.
/// Structural completion does not establish monetary, script, or consensus validity; the caller
/// must also validate any enclosing frame before requesting commit. Callback exceptions propagate
/// and fault the parser without guaranteeing an abort callback, so sinks must clean up their own
/// staged effects on exceptional termination.
/// </remarks>
public interface ILegacyTransactionSink
{
    /// <summary>Begins a provisional lifecycle after the version and canonical nonzero input count are read.</summary>
    /// <param name="version">The raw signed transaction version.</param>
    /// <param name="inputCount">The declared input count; it is not a safe collection-allocation size.</param>
    void OnTransactionStarted(int version, ulong inputCount);

    /// <summary>Begins an input after its previous-output reference and script length have been read.</summary>
    /// <param name="inputIndex">The zero-based input index.</param>
    /// <param name="previousOutput">The copied reference value; no existence or spendability check is implied.</param>
    /// <param name="scriptLength">The declared script length in bytes; it may exceed available memory.</param>
    void OnInputStarted(ulong inputIndex, in OutPoint previousOutput, ulong scriptLength);

    /// <summary>Receives a nonempty borrowed input-script chunk; chunk boundaries have no script meaning.</summary>
    /// <param name="inputIndex">The zero-based input index.</param>
    /// <param name="script">Bytes valid only during this callback; empty scripts produce no chunk callbacks.</param>
    void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script);

    /// <summary>Completes the input after its script and sequence have been read.</summary>
    /// <param name="inputIndex">The zero-based input index.</param>
    /// <param name="sequence">The raw sequence field, without lock-time or finality evaluation.</param>
    void OnInputCompleted(ulong inputIndex, uint sequence);

    /// <summary>Begins the output section after its canonical nonzero count has been read.</summary>
    /// <param name="outputCount">The declared count; it is not a safe collection-allocation size.</param>
    void OnOutputsStarted(ulong outputCount);

    /// <summary>Begins an output after its raw signed value and script length have been read.</summary>
    /// <param name="outputIndex">The zero-based output index.</param>
    /// <param name="valueSatoshis">The raw signed value, including negative or out-of-range values.</param>
    /// <param name="scriptLength">The declared script length in bytes; it may exceed available memory.</param>
    void OnOutputStarted(ulong outputIndex, long valueSatoshis, ulong scriptLength);

    /// <summary>Receives a nonempty borrowed output-script chunk; chunk boundaries have no script meaning.</summary>
    /// <param name="outputIndex">The zero-based output index.</param>
    /// <param name="script">Bytes valid only during this callback; empty scripts produce no chunk callbacks.</param>
    void OnOutputScriptChunk(ulong outputIndex, ReadOnlySpan<byte> script);

    /// <summary>Completes an output after its script has been consumed.</summary>
    /// <param name="outputIndex">The zero-based output index.</param>
    void OnOutputCompleted(ulong outputIndex);

    /// <summary>Publishes the structurally complete transaction when the caller explicitly commits it.</summary>
    /// <param name="summary">Copied metadata and the transaction identifier; no script storage is retained.</param>
    void OnTransactionCommitted(in LegacyTransactionSummary summary);

    /// <summary>Discards an active provisional lifecycle on explicit abort or detected malformed input.</summary>
    /// <remarks>Not guaranteed after callback exceptions, and not invoked by parser disposal.</remarks>
    void OnTransactionAborted();
}
