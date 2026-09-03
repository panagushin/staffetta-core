using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Encoding;

namespace Staffetta.Core.Protocol.Transactions;

/// <summary>
/// Incrementally parses one structurally canonical non-witness transaction without retaining scripts or
/// allocating from declared counts and lengths.
/// </summary>
/// <remarks>
/// Instances are single-consumer and not thread-safe. Sink callbacks are provisional until
/// <see cref="Commit(out LegacyTransactionSummary)"/> succeeds. Malformed input, callback exceptions, and callback reentrancy
/// permanently fault the instance. After a successful commit or explicit <see cref="Abort"/>, the
/// instance is reset for another transaction.
/// Canonical CompactSize encodings and nonzero input/output counts are required, but script bytes
/// are opaque and all signed output values are preserved. Monetary ranges, script execution,
/// UTXO availability, transaction finality, and consensus validity are outside this parser.
/// Enclosing-frame length and checksum validation remain the caller's responsibility before commit.
/// </remarks>
public sealed class LegacyTransactionParser : IDisposable
{
    private const int MaximumScratchLength = Hash256.Length + sizeof(uint);

    private readonly ILegacyTransactionSink _sink;
    private readonly LegacyTransactionHashMode _hashMode;
    private readonly byte[] _scratch = new byte[MaximumScratchLength];
    private readonly IncrementalHash? _firstHash;

    private IncrementalCompactSizeReader _compactSize;
    private ParseState _state;
    private int _scratchLength;
    private int _version;
    private ulong _inputCount;
    private ulong _inputIndex;
    private ulong _outputCount;
    private ulong _outputIndex;
    private ulong _scriptBytesRemaining;
    private ulong _totalInputScriptLength;
    private ulong _totalOutputScriptLength;
    private ulong _serializedLength;
    private OutPoint _previousOutput;
    private long _outputValueSatoshis;
    private uint _lockTime;
    private bool _sinkLifecycleStarted;
    private bool _isCallingSink;
    private bool _callbackReentryDetected;
    private bool _isFaulted;
    private bool _isDisposed;

    /// <summary>Creates a reusable parser that reports provisional structure to the sink.</summary>
    /// <param name="sink">The synchronous sink receiving borrowed script chunks and provisional callbacks.</param>
    /// <exception cref="ArgumentNullException"><paramref name="sink"/> is null.</exception>
    public LegacyTransactionParser(ILegacyTransactionSink sink)
        : this(sink, LegacyTransactionHashMode.Internal)
    {
    }

    internal LegacyTransactionParser(
        ILegacyTransactionSink sink,
        LegacyTransactionHashMode hashMode)
    {
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        if (hashMode is not LegacyTransactionHashMode.Internal and
            not LegacyTransactionHashMode.ExternalValidatedPayload)
        {
            throw new ArgumentOutOfRangeException(nameof(hashMode));
        }

        _hashMode = hashMode;
        _firstHash = hashMode == LegacyTransactionHashMode.Internal
            ? IncrementalHash.CreateHash(HashAlgorithmName.SHA256)
            : null;
        _state = ParseState.Version;
    }

    /// <summary>Gets whether all transaction fields have been consumed and await an explicit commit.</summary>
    /// <remarks>This reports parse position only; a fault or disposal still prevents commit.</remarks>
    public bool IsReadyToCommit => _state == ParseState.ReadyToCommit;

    /// <summary>Gets whether an unrecoverable parse or callback failure has occurred.</summary>
    public bool IsFaulted => _isFaulted;

    /// <summary>Consumes up to one complete transaction and leaves trailing bytes untouched.</summary>
    /// <param name="source">The next byte chunk; script spans are borrowed only during callbacks.</param>
    /// <param name="bytesConsumed">Bytes accepted from this call, including incomplete fields and bytes accepted before a callback failure.</param>
    /// <returns>
    /// <see cref="OperationStatus.Done"/> when ready to commit,
    /// <see cref="OperationStatus.NeedMoreData"/> while incomplete, or
    /// <see cref="OperationStatus.InvalidData"/> for malformed input, length overflow, or a faulted instance.
    /// </returns>
    /// <remarks>
    /// Resume with the unconsumed suffix; accepted bytes are not replayed. Once ready, further calls
    /// return Done without consumption until commit or abort. Callback exceptions propagate; a
    /// sink-thrown overflow exception is instead treated as invalid data by the parser.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The parser has been disposed.</exception>
    /// <exception cref="InvalidOperationException">The parser is re-entered from a sink callback.</exception>
    public OperationStatus Consume(ReadOnlySpan<byte> source, out int bytesConsumed)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        bytesConsumed = 0;
        ThrowIfReentrant();
        if (_isFaulted)
        {
            return OperationStatus.InvalidData;
        }

        if (_state == ParseState.ReadyToCommit)
        {
            return OperationStatus.Done;
        }

        OperationStatus status;
        try
        {
            status = ConsumeCore(source, ref bytesConsumed);
        }
        catch (OverflowException)
        {
            status = OperationStatus.InvalidData;
        }
        catch
        {
            _isFaulted = true;
            throw;
        }

        if (status == OperationStatus.InvalidData)
        {
            FaultAndNotifyAbort();
        }

        return status;
    }

    /// <summary>Publishes a structurally complete summary and resets for the next transaction.</summary>
    /// <param name="summary">The computed metadata and transaction identifier on success; not usable if a callback throws.</param>
    /// <returns><see cref="OperationStatus.Done"/> on commit, or <see cref="OperationStatus.InvalidData"/> if incomplete or faulted.</returns>
    /// <remarks>
    /// Call only after any enclosing frame has been validated. Incomplete commit attempts do not
    /// discard buffered input. The transaction identifier is double SHA-256 of consumed transaction
    /// bytes only. A commit-callback exception propagates and permanently faults the instance.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The parser has been disposed.</exception>
    /// <exception cref="InvalidOperationException">The parser is re-entered from a sink callback.</exception>
    public OperationStatus Commit(out LegacyTransactionSummary summary)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        summary = default;
        ThrowIfReentrant();
        if (_hashMode != LegacyTransactionHashMode.Internal)
        {
            return OperationStatus.InvalidData;
        }

        if (_isFaulted || _state != ParseState.ReadyToCommit)
        {
            return OperationStatus.InvalidData;
        }

        Span<byte> firstHash = stackalloc byte[Hash256.Length];
        if (!_firstHash!.TryGetHashAndReset(firstHash, out var firstHashLength) ||
            firstHashLength != Hash256.Length)
        {
            FaultAndNotifyAbort();
            return OperationStatus.InvalidData;
        }

        Span<byte> secondHash = stackalloc byte[Hash256.Length];
        SHA256.HashData(firstHash, secondHash);
        if (Hash256.TryCreate(secondHash, out var transactionId) != OperationStatus.Done)
        {
            FaultAndNotifyAbort();
            return OperationStatus.InvalidData;
        }

        return CommitCore(transactionId, out summary);
    }

    internal OperationStatus Commit(
        in Hash256 validatedPayloadHash,
        ulong validatedPayloadLength,
        out LegacyTransactionSummary summary)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        summary = default;
        ThrowIfReentrant();
        if (_hashMode != LegacyTransactionHashMode.ExternalValidatedPayload ||
            _isFaulted ||
            _state != ParseState.ReadyToCommit ||
            validatedPayloadLength != _serializedLength)
        {
            return OperationStatus.InvalidData;
        }

        // The digest and length jointly identify the byte range validated by the framing layer.
        return CommitCore(validatedPayloadHash, out summary);
    }

    private OperationStatus CommitCore(
        in Hash256 transactionId,
        out LegacyTransactionSummary summary)
    {
        summary = new LegacyTransactionSummary(
            _version,
            _inputCount,
            _outputCount,
            _totalInputScriptLength,
            _totalOutputScriptLength,
            _lockTime,
            _serializedLength,
            transactionId);

        try
        {
            NotifyTransactionCommitted(summary);
        }
        catch
        {
            _isFaulted = true;
            throw;
        }

        ResetCore();
        return OperationStatus.Done;
    }

    /// <summary>Discards an active provisional lifecycle and resets the parser.</summary>
    /// <remarks>Notifies the sink only if its lifecycle has started. A faulted parser cannot be recovered this way.</remarks>
    /// <exception cref="ObjectDisposedException">The parser has been disposed.</exception>
    /// <exception cref="InvalidOperationException">The parser is faulted or is re-entered from a sink callback.</exception>
    public void Abort()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        ThrowIfReentrant();
        if (_isFaulted)
        {
            throw new InvalidOperationException("A faulted transaction parser cannot be reset.");
        }

        try
        {
            NotifyAbortIfStarted();
        }
        catch
        {
            _isFaulted = true;
            throw;
        }

        if (_firstHash is not null)
        {
            Span<byte> discardedHash = stackalloc byte[Hash256.Length];
            _firstHash.TryGetHashAndReset(discardedHash, out _);
        }

        ResetCore();
    }

    /// <summary>Releases hashing resources without invoking an abort callback.</summary>
    /// <remarks>Call <see cref="Abort"/> first if a nonfaulted provisional lifecycle needs an abort notification. Repeated disposal is harmless.</remarks>
    /// <exception cref="InvalidOperationException">Disposal is attempted from a sink callback.</exception>
    public void Dispose()
    {
        if (_isDisposed)
        {
            return;
        }

        ThrowIfReentrant();
        _firstHash?.Dispose();
        _isDisposed = true;
    }

    private OperationStatus ConsumeCore(ReadOnlySpan<byte> source, ref int offset)
    {
        while (offset < source.Length)
        {
            switch (_state)
            {
                case ParseState.Version:
                    if (!ReadFixed(source, ref offset, sizeof(int)))
                    {
                        return OperationStatus.NeedMoreData;
                    }

                    _version = BinaryPrimitives.ReadInt32LittleEndian(_scratch);
                    ClearScratch();
                    _state = ParseState.InputCount;
                    break;

                case ParseState.InputCount:
                    var inputCountStatus = ReadCompactSize(source, ref offset, requireNonZero: true, out _inputCount);
                    if (inputCountStatus != OperationStatus.Done)
                    {
                        return inputCountStatus;
                    }

                    _sinkLifecycleStarted = true;
                    NotifyTransactionStarted();
                    _state = ParseState.InputOutPoint;
                    break;

                case ParseState.InputOutPoint:
                    if (!ReadFixed(source, ref offset, MaximumScratchLength))
                    {
                        return OperationStatus.NeedMoreData;
                    }

                    _ = Hash256.TryCreate(_scratch.AsSpan(0, Hash256.Length), out var previousTransactionId);
                    _previousOutput = new OutPoint(
                        previousTransactionId,
                        BinaryPrimitives.ReadUInt32LittleEndian(_scratch.AsSpan(Hash256.Length)));
                    ClearScratch();
                    _state = ParseState.InputScriptLength;
                    break;

                case ParseState.InputScriptLength:
                    var inputScriptStatus = ReadCompactSize(source, ref offset, requireNonZero: false, out var inputScriptLength);
                    if (inputScriptStatus != OperationStatus.Done)
                    {
                        return inputScriptStatus;
                    }

                    _totalInputScriptLength = checked(_totalInputScriptLength + inputScriptLength);
                    _scriptBytesRemaining = inputScriptLength;
                    NotifyInputStarted(inputScriptLength);
                    _state = inputScriptLength == 0 ? ParseState.InputSequence : ParseState.InputScript;
                    break;

                case ParseState.InputScript:
                    ConsumeScript(source, ref offset, isInput: true);
                    if (_scriptBytesRemaining != 0)
                    {
                        return OperationStatus.NeedMoreData;
                    }

                    _state = ParseState.InputSequence;
                    break;

                case ParseState.InputSequence:
                    if (!ReadFixed(source, ref offset, sizeof(uint)))
                    {
                        return OperationStatus.NeedMoreData;
                    }

                    var sequence = BinaryPrimitives.ReadUInt32LittleEndian(_scratch);
                    ClearScratch();
                    NotifyInputCompleted(sequence);
                    _inputIndex++;
                    _state = _inputIndex == _inputCount
                        ? ParseState.OutputCount
                        : ParseState.InputOutPoint;
                    break;

                case ParseState.OutputCount:
                    var outputCountStatus = ReadCompactSize(source, ref offset, requireNonZero: true, out _outputCount);
                    if (outputCountStatus != OperationStatus.Done)
                    {
                        return outputCountStatus;
                    }

                    NotifyOutputsStarted();
                    _state = ParseState.OutputValue;
                    break;

                case ParseState.OutputValue:
                    if (!ReadFixed(source, ref offset, sizeof(long)))
                    {
                        return OperationStatus.NeedMoreData;
                    }

                    _outputValueSatoshis = BinaryPrimitives.ReadInt64LittleEndian(_scratch);
                    ClearScratch();
                    _state = ParseState.OutputScriptLength;
                    break;

                case ParseState.OutputScriptLength:
                    var outputScriptStatus = ReadCompactSize(source, ref offset, requireNonZero: false, out var outputScriptLength);
                    if (outputScriptStatus != OperationStatus.Done)
                    {
                        return outputScriptStatus;
                    }

                    _totalOutputScriptLength = checked(_totalOutputScriptLength + outputScriptLength);
                    _scriptBytesRemaining = outputScriptLength;
                    NotifyOutputStarted(outputScriptLength);
                    _state = outputScriptLength == 0 ? ParseState.OutputComplete : ParseState.OutputScript;
                    break;

                case ParseState.OutputScript:
                    ConsumeScript(source, ref offset, isInput: false);
                    if (_scriptBytesRemaining != 0)
                    {
                        return OperationStatus.NeedMoreData;
                    }

                    _state = ParseState.OutputComplete;
                    break;

                case ParseState.OutputComplete:
                    NotifyOutputCompleted();
                    _outputIndex++;
                    _state = _outputIndex == _outputCount
                        ? ParseState.LockTime
                        : ParseState.OutputValue;
                    break;

                case ParseState.LockTime:
                    if (!ReadFixed(source, ref offset, sizeof(uint)))
                    {
                        return OperationStatus.NeedMoreData;
                    }

                    _lockTime = BinaryPrimitives.ReadUInt32LittleEndian(_scratch);
                    ClearScratch();
                    _state = ParseState.ReadyToCommit;
                    return OperationStatus.Done;

                default:
                    return OperationStatus.InvalidData;
            }
        }

        return _state == ParseState.ReadyToCommit
            ? OperationStatus.Done
            : OperationStatus.NeedMoreData;
    }

    private OperationStatus ReadCompactSize(
        ReadOnlySpan<byte> source,
        ref int offset,
        bool requireNonZero,
        out ulong value)
    {
        value = 0;
        var compactSizeOffset = offset;
        var compactSizeLength = _compactSize.Consume(source[offset..]);
        Accept(source.Slice(compactSizeOffset, compactSizeLength), ref offset);
        if (!_compactSize.IsComplete)
        {
            return OperationStatus.NeedMoreData;
        }

        if (!_compactSize.IsCanonical || (requireNonZero && _compactSize.Value == 0))
        {
            return OperationStatus.InvalidData;
        }

        value = _compactSize.Value;
        _compactSize = default;
        return OperationStatus.Done;
    }

    private bool ReadFixed(ReadOnlySpan<byte> source, ref int offset, int requiredLength)
    {
        var copiedLength = Math.Min(source.Length - offset, requiredLength - _scratchLength);
        var accepted = source.Slice(offset, copiedLength);
        Accept(accepted, ref offset);
        accepted.CopyTo(_scratch.AsSpan(_scratchLength));
        _scratchLength += copiedLength;
        return _scratchLength == requiredLength;
    }

    private void ConsumeScript(ReadOnlySpan<byte> source, ref int offset, bool isInput)
    {
        var length = (int)Math.Min((ulong)(source.Length - offset), _scriptBytesRemaining);
        if (length == 0)
        {
            return;
        }

        var script = source.Slice(offset, length);
        Accept(script, ref offset);
        _scriptBytesRemaining -= (uint)length;
        if (isInput)
        {
            NotifyInputScriptChunk(script);
        }
        else
        {
            NotifyOutputScriptChunk(script);
        }
    }

    private void FaultAndNotifyAbort()
    {
        _isFaulted = true;
        NotifyAbortIfStarted();
    }

    private void NotifyAbortIfStarted()
    {
        if (!_sinkLifecycleStarted)
        {
            return;
        }

        _sinkLifecycleStarted = false;
        _isCallingSink = true;
        try
        {
            _sink.OnTransactionAborted();
        }
        finally
        {
            CompleteSinkCallback();
        }
    }

    private void NotifyTransactionStarted()
    {
        _isCallingSink = true;
        try
        {
            _sink.OnTransactionStarted(_version, _inputCount);
        }
        finally
        {
            CompleteSinkCallback();
        }
    }

    private void NotifyInputStarted(ulong scriptLength)
    {
        _isCallingSink = true;
        try
        {
            _sink.OnInputStarted(_inputIndex, _previousOutput, scriptLength);
        }
        finally
        {
            CompleteSinkCallback();
        }
    }

    private void NotifyInputScriptChunk(ReadOnlySpan<byte> script)
    {
        _isCallingSink = true;
        try
        {
            _sink.OnInputScriptChunk(_inputIndex, script);
        }
        finally
        {
            CompleteSinkCallback();
        }
    }

    private void NotifyInputCompleted(uint sequence)
    {
        _isCallingSink = true;
        try
        {
            _sink.OnInputCompleted(_inputIndex, sequence);
        }
        finally
        {
            CompleteSinkCallback();
        }
    }

    private void NotifyOutputsStarted()
    {
        _isCallingSink = true;
        try
        {
            _sink.OnOutputsStarted(_outputCount);
        }
        finally
        {
            CompleteSinkCallback();
        }
    }

    private void NotifyOutputStarted(ulong scriptLength)
    {
        _isCallingSink = true;
        try
        {
            _sink.OnOutputStarted(_outputIndex, _outputValueSatoshis, scriptLength);
        }
        finally
        {
            CompleteSinkCallback();
        }
    }

    private void NotifyOutputScriptChunk(ReadOnlySpan<byte> script)
    {
        _isCallingSink = true;
        try
        {
            _sink.OnOutputScriptChunk(_outputIndex, script);
        }
        finally
        {
            CompleteSinkCallback();
        }
    }

    private void NotifyOutputCompleted()
    {
        _isCallingSink = true;
        try
        {
            _sink.OnOutputCompleted(_outputIndex);
        }
        finally
        {
            CompleteSinkCallback();
        }
    }

    private void NotifyTransactionCommitted(in LegacyTransactionSummary summary)
    {
        _isCallingSink = true;
        try
        {
            _sink.OnTransactionCommitted(summary);
        }
        finally
        {
            CompleteSinkCallback();
        }
    }

    private void CompleteSinkCallback()
    {
        _isCallingSink = false;
        if (_callbackReentryDetected)
        {
            throw new InvalidOperationException(
                "Legacy transaction parser reentrancy was caught inside a sink callback.");
        }
    }

    private void ThrowIfReentrant()
    {
        if (!_isCallingSink)
        {
            return;
        }

        _isFaulted = true;
        _callbackReentryDetected = true;
        throw new InvalidOperationException("Legacy transaction parser cannot be re-entered from a sink callback.");
    }

    private void Accept(ReadOnlySpan<byte> accepted, ref int offset)
    {
        if (accepted.IsEmpty)
        {
            return;
        }

        var serializedLength = checked(_serializedLength + (ulong)accepted.Length);
        _firstHash?.AppendData(accepted);
        _serializedLength = serializedLength;
        offset += accepted.Length;
    }

    private void ClearScratch()
    {
        _scratch.AsSpan(0, _scratchLength).Clear();
        _scratchLength = 0;
    }

    private void ResetCore()
    {
        ClearScratch();
        _compactSize = default;
        _state = ParseState.Version;
        _version = 0;
        _inputCount = 0;
        _inputIndex = 0;
        _outputCount = 0;
        _outputIndex = 0;
        _scriptBytesRemaining = 0;
        _totalInputScriptLength = 0;
        _totalOutputScriptLength = 0;
        _serializedLength = 0;
        _previousOutput = default;
        _outputValueSatoshis = 0;
        _lockTime = 0;
        _sinkLifecycleStarted = false;
        _callbackReentryDetected = false;
    }

    private enum ParseState
    {
        Version,
        InputCount,
        InputOutPoint,
        InputScriptLength,
        InputScript,
        InputSequence,
        OutputCount,
        OutputValue,
        OutputScriptLength,
        OutputScript,
        OutputComplete,
        LockTime,
        ReadyToCommit,
    }
}

internal enum LegacyTransactionHashMode
{
    Internal,
    ExternalValidatedPayload,
}
