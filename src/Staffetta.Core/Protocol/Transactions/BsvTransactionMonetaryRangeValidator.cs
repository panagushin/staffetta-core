namespace Staffetta.Core.Protocol.Transactions;

internal sealed class BsvTransactionMonetaryRangeValidator : ILegacyTransactionSink
{
    internal const long MaximumMoneySatoshis = 2_100_000_000_000_000;

    private readonly ILegacyTransactionSink _inner;

    private long _totalOutputValueSatoshis;
    private BsvTransactionMonetaryValidationReason _reason;
    private ulong _invalidOutputIndex;
    private long _invalidOutputValueSatoshis;
    private long _invalidTotalOutputValueSatoshis;
    private BsvTransactionMonetaryValidation _committedValidation;
    private bool _hasActiveLifecycle;
    private bool _hasCommittedValidation;

    internal BsvTransactionMonetaryRangeValidator(ILegacyTransactionSink inner) =>
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));

    internal bool TryGetCommittedValidation(out BsvTransactionMonetaryValidation validation)
    {
        validation = _committedValidation;
        return _hasCommittedValidation;
    }

    public void OnTransactionStarted(int version, ulong inputCount)
    {
        ResetValidation();
        _hasActiveLifecycle = true;
        _inner.OnTransactionStarted(version, inputCount);
    }

    public void OnInputStarted(
        ulong inputIndex,
        in OutPoint previousOutput,
        ulong scriptLength) =>
        _inner.OnInputStarted(inputIndex, previousOutput, scriptLength);

    public void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script) =>
        _inner.OnInputScriptChunk(inputIndex, script);

    public void OnInputCompleted(ulong inputIndex, uint sequence) =>
        _inner.OnInputCompleted(inputIndex, sequence);

    public void OnOutputsStarted(ulong outputCount) =>
        _inner.OnOutputsStarted(outputCount);

    public void OnOutputStarted(
        ulong outputIndex,
        long valueSatoshis,
        ulong scriptLength)
    {
        if (_reason == BsvTransactionMonetaryValidationReason.None)
        {
            if (valueSatoshis < 0)
            {
                RecordInvalid(
                    BsvTransactionMonetaryValidationReason.NegativeOutput,
                    outputIndex,
                    valueSatoshis,
                    _totalOutputValueSatoshis);
            }
            else if (valueSatoshis > MaximumMoneySatoshis)
            {
                RecordInvalid(
                    BsvTransactionMonetaryValidationReason.OutputExceedsMaximum,
                    outputIndex,
                    valueSatoshis,
                    _totalOutputValueSatoshis);
            }
            else if (valueSatoshis > MaximumMoneySatoshis - _totalOutputValueSatoshis)
            {
                RecordInvalid(
                    BsvTransactionMonetaryValidationReason.AggregateExceedsMaximum,
                    outputIndex,
                    valueSatoshis,
                    _totalOutputValueSatoshis + valueSatoshis);
            }
            else
            {
                _totalOutputValueSatoshis += valueSatoshis;
            }
        }

        _inner.OnOutputStarted(outputIndex, valueSatoshis, scriptLength);
    }

    public void OnOutputScriptChunk(ulong outputIndex, ReadOnlySpan<byte> script) =>
        _inner.OnOutputScriptChunk(outputIndex, script);

    public void OnOutputCompleted(ulong outputIndex) =>
        _inner.OnOutputCompleted(outputIndex);

    public void OnTransactionCommitted(in LegacyTransactionSummary summary)
    {
        var validation = new BsvTransactionMonetaryValidation(
            summary.TransactionId,
            _reason,
            _invalidOutputIndex,
            _invalidOutputValueSatoshis,
            _reason == BsvTransactionMonetaryValidationReason.None
                ? _totalOutputValueSatoshis
                : _invalidTotalOutputValueSatoshis);

        if (validation.IsValid)
        {
            _inner.OnTransactionCommitted(summary);
        }
        else
        {
            _inner.OnTransactionAborted();
        }

        _hasActiveLifecycle = false;
        _committedValidation = validation;
        _hasCommittedValidation = true;
    }

    public void OnTransactionAborted()
    {
        if (_hasActiveLifecycle)
        {
            _inner.OnTransactionAborted();
        }

        ResetValidation();
        _hasActiveLifecycle = false;
    }

    private void RecordInvalid(
        BsvTransactionMonetaryValidationReason reason,
        ulong outputIndex,
        long valueSatoshis,
        long totalOutputValueSatoshis)
    {
        _reason = reason;
        _invalidOutputIndex = outputIndex;
        _invalidOutputValueSatoshis = valueSatoshis;
        _invalidTotalOutputValueSatoshis = totalOutputValueSatoshis;
    }

    private void ResetValidation()
    {
        _totalOutputValueSatoshis = 0;
        _reason = BsvTransactionMonetaryValidationReason.None;
        _invalidOutputIndex = 0;
        _invalidOutputValueSatoshis = 0;
        _invalidTotalOutputValueSatoshis = 0;
        _committedValidation = default;
        _hasCommittedValidation = false;
    }
}
