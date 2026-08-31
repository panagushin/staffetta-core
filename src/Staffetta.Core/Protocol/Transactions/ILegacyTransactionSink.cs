namespace Staffetta.Core.Protocol.Transactions;

/// <summary>
/// Receives provisional legacy-transaction structure and borrowed script chunks.
/// </summary>
/// <remarks>
/// Implementations must not publish provisional effects before <see cref="OnTransactionCommitted"/>.
/// Script spans are valid only for the duration of their callback. A sink callback must not
/// re-enter the parser that invoked it.
/// </remarks>
public interface ILegacyTransactionSink
{
    void OnTransactionStarted(int version, ulong inputCount);

    void OnInputStarted(ulong inputIndex, in OutPoint previousOutput, ulong scriptLength);

    void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script);

    void OnInputCompleted(ulong inputIndex, uint sequence);

    void OnOutputsStarted(ulong outputCount);

    void OnOutputStarted(ulong outputIndex, long valueSatoshis, ulong scriptLength);

    void OnOutputScriptChunk(ulong outputIndex, ReadOnlySpan<byte> script);

    void OnOutputCompleted(ulong outputIndex);

    void OnTransactionCommitted(in LegacyTransactionSummary summary);

    void OnTransactionAborted();
}
