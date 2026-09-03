using System.Buffers;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Wire;

/// <summary>
/// Incrementally frames wire messages without retaining their payloads.
/// </summary>
/// <remarks>
/// Instances are single-consumer and not thread-safe. Sink callbacks and ingress policies
/// cannot call Consume, <see cref="ConsumeSingleFrame"/>, <see cref="CompleteEndOfInput"/>, or
/// <see cref="Dispose"/> on the same instance. A malformed frame, an admission rejection, or an
/// exception from a callback permanently faults the instance. Callback exceptions are propagated
/// and the event that caused one is never replayed.
/// </remarks>
public sealed class MessageIngressStateMachine : IDisposable
{
    private readonly byte[] _expectedNetworkMagic;
    private readonly ulong _maximumPayloadLength;
    private readonly IMessageIngressSink _sink;
    private readonly IMessageIngressAdmissionPolicy? _admissionPolicy;
    private readonly IMessageIngressPayloadHashPolicy? _payloadHashPolicy;
    private readonly byte[] _headerBuffer = new byte[MessageHeaderCodec.ExtendedHeaderLength];

    private MessagePayloadValidator? _payloadValidator;
    private int _headerLength;
    private bool _isConsuming;
    private bool _isEvaluatingPolicy;
    private bool _isCallingSink;
    private bool _sinkCallbackReentryDetected;
    private bool _isCompleted;
    private bool _isFaulted;
    private bool _isDisposed;

    /// <summary>Creates ingress with a copied network magic and no per-header admission or extended-hash policy.</summary>
    /// <param name="expectedNetworkMagic">Exactly four network-magic bytes; copied during construction.</param>
    /// <param name="maximumPayloadLength">The inclusive payload-length limit, checked before starting a frame.</param>
    /// <param name="sink">The synchronous frame sink; retained but not disposed by ingress.</param>
    /// <exception cref="ArgumentException">Network magic does not contain exactly four bytes.</exception>
    /// <exception cref="ArgumentNullException">The sink is null.</exception>
    public MessageIngressStateMachine(
        ReadOnlySpan<byte> expectedNetworkMagic,
        ulong maximumPayloadLength,
        IMessageIngressSink sink)
        : this(
            expectedNetworkMagic,
            maximumPayloadLength,
            sink,
            admissionPolicy: null,
            payloadHashPolicy: null)
    {
    }

    /// <summary>Creates ingress with an optional header admission policy and length-only extended validation.</summary>
    /// <param name="expectedNetworkMagic">Exactly four network-magic bytes; copied during construction.</param>
    /// <param name="maximumPayloadLength">The inclusive payload-length limit.</param>
    /// <param name="sink">The synchronous frame sink; retained but not disposed by ingress.</param>
    /// <param name="admissionPolicy">An optional retained policy called before payload processing.</param>
    /// <exception cref="ArgumentException">Network magic does not contain exactly four bytes.</exception>
    /// <exception cref="ArgumentNullException">The sink is null.</exception>
    public MessageIngressStateMachine(
        ReadOnlySpan<byte> expectedNetworkMagic,
        ulong maximumPayloadLength,
        IMessageIngressSink sink,
        IMessageIngressAdmissionPolicy? admissionPolicy)
        : this(expectedNetworkMagic, maximumPayloadLength, sink, admissionPolicy, payloadHashPolicy: null)
    {
    }

    /// <summary>Creates ingress with optional admission and extended-payload hashing policies.</summary>
    /// <param name="expectedNetworkMagic">Exactly four network-magic bytes; copied during construction.</param>
    /// <param name="maximumPayloadLength">The inclusive payload-length limit.</param>
    /// <param name="sink">The synchronous frame sink; retained but not disposed by ingress.</param>
    /// <param name="admissionPolicy">An optional retained policy called before payload processing.</param>
    /// <param name="payloadHashPolicy">An optional retained policy selecting extended frames whose full digest is needed.</param>
    /// <exception cref="ArgumentException">Network magic does not contain exactly four bytes.</exception>
    /// <exception cref="ArgumentNullException">The sink is null.</exception>
    public MessageIngressStateMachine(
        ReadOnlySpan<byte> expectedNetworkMagic,
        ulong maximumPayloadLength,
        IMessageIngressSink sink,
        IMessageIngressAdmissionPolicy? admissionPolicy,
        IMessageIngressPayloadHashPolicy? payloadHashPolicy)
    {
        if (expectedNetworkMagic.Length != MessageHeaderCodec.NetworkMagicLength)
        {
            throw new ArgumentException(
                $"Network magic must contain exactly {MessageHeaderCodec.NetworkMagicLength} bytes.",
                nameof(expectedNetworkMagic));
        }

        _expectedNetworkMagic = expectedNetworkMagic.ToArray();
        _maximumPayloadLength = maximumPayloadLength;
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _admissionPolicy = admissionPolicy;
        _payloadHashPolicy = payloadHashPolicy;
    }

    /// <summary>Gets whether end of input was declared; inspect IsFaulted to distinguish clean completion from truncation.</summary>
    public bool IsCompleted => _isCompleted;

    /// <summary>Gets whether a permanent framing, policy, or callback failure prevents further consumption.</summary>
    public bool IsFaulted => _isFaulted;

    /// <summary>Incrementally consumes as many frames as the supplied bytes permit.</summary>
    /// <param name="source">Caller-owned input; only incomplete header bytes are copied and retained.</param>
    /// <param name="bytesConsumed">Bytes accepted from this call, including those accepted before an error or callback exception.</param>
    /// <returns>Done at a completed frame boundary; NeedMoreData for an incomplete next header or payload; InvalidData for a permanent fault.</returns>
    /// <remarks>Use the consumed count even on failure. No payload backpressure is supported. Sink payload bytes remain provisional until completion and higher-level validation.</remarks>
    /// <exception cref="ObjectDisposedException">Ingress has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Ingress is re-entered or clean end of input was already declared.</exception>
    public OperationStatus Consume(
        ReadOnlySpan<byte> source,
        out int bytesConsumed) =>
        ConsumeCore(source, stopAfterFrame: false, out bytesConsumed);

    /// <summary>
    /// Consumes no more than one wire frame, leaving any following frame untouched.
    /// </summary>
    /// <param name="source">Caller-owned input; no payload slice is retained.</param>
    /// <param name="bytesConsumed">Bytes accepted from this call, including bytes accepted before failure; any following frame is untouched.</param>
    /// <returns>Done after one frame, NeedMoreData for an incomplete frame, or InvalidData for a permanent fault.</returns>
    /// <exception cref="ObjectDisposedException">Ingress has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Ingress is re-entered or clean end of input was already declared.</exception>
    public OperationStatus ConsumeSingleFrame(
        ReadOnlySpan<byte> source,
        out int bytesConsumed) =>
        ConsumeCore(source, stopAfterFrame: true, out bytesConsumed);

    private OperationStatus ConsumeCore(
        ReadOnlySpan<byte> source,
        bool stopAfterFrame,
        out int bytesConsumed)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        bytesConsumed = 0;
        ThrowIfCalledFromSinkCallback("Message ingress cannot be re-entered from a sink callback.");
        if (_isConsuming)
        {
            MarkReentry();
            throw new InvalidOperationException("Message ingress cannot be re-entered.");
        }

        if (_isFaulted)
        {
            return OperationStatus.InvalidData;
        }

        if (_isCompleted)
        {
            throw new InvalidOperationException("Message ingress has reached end of input.");
        }

        _isConsuming = true;
        try
        {
            while (true)
            {
                if (_payloadValidator is null)
                {
                    var headerBytesConsumed = 0;
                    OperationStatus headerStatus;
                    try
                    {
                        headerStatus = ConsumeHeader(source[bytesConsumed..], out headerBytesConsumed);
                    }
                    catch
                    {
                        bytesConsumed += headerBytesConsumed;
                        throw;
                    }

                    bytesConsumed += headerBytesConsumed;
                    if (headerStatus != OperationStatus.Done)
                    {
                        return headerStatus;
                    }
                }

                var payloadBytesConsumed = 0;
                OperationStatus payloadStatus;
                try
                {
                    payloadStatus = ConsumePayload(source[bytesConsumed..], out payloadBytesConsumed);
                }
                catch
                {
                    bytesConsumed += payloadBytesConsumed;
                    throw;
                }

                bytesConsumed += payloadBytesConsumed;
                if (payloadStatus != OperationStatus.Done)
                {
                    return payloadStatus;
                }

                if (stopAfterFrame || bytesConsumed == source.Length)
                {
                    return OperationStatus.Done;
                }
            }
        }
        finally
        {
            _isConsuming = false;
        }
    }

    /// <summary>Declares no more input and checks that ingress ended exactly at a frame boundary.</summary>
    /// <returns>Done for a clean boundary or repeated clean completion; InvalidData for a fault or truncated frame.</returns>
    /// <remarks>A truncated started payload receives an abort callback; an incomplete header has no started frame to notify. Completion is terminal.</remarks>
    /// <exception cref="ObjectDisposedException">Ingress has been disposed.</exception>
    /// <exception cref="InvalidOperationException">The call re-enters ingress from processing or a callback.</exception>
    public OperationStatus CompleteEndOfInput()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        ThrowIfCalledFromSinkCallback("Message ingress cannot be completed from a sink callback.");
        if (_isConsuming)
        {
            MarkReentry();
            throw new InvalidOperationException("Message ingress cannot be completed from a sink callback.");
        }

        if (_isFaulted)
        {
            return OperationStatus.InvalidData;
        }

        if (_isCompleted)
        {
            return OperationStatus.Done;
        }

        _isCompleted = true;
        if (_payloadValidator is not null)
        {
            _payloadValidator.Dispose();
            _payloadValidator = null;
            _isFaulted = true;
            NotifyCompleted(new MessageIngressResult(MessageIngressCompletion.FrameAborted, null));
            return OperationStatus.InvalidData;
        }

        if (_headerLength > 0)
        {
            _isFaulted = true;
            return OperationStatus.InvalidData;
        }

        return OperationStatus.Done;
    }

    /// <summary>Releases validation resources without issuing completion or abort callbacks.</summary>
    /// <remarks>Call CompleteEndOfInput first when truncation must be reported to the sink. Repeated disposal is harmless.</remarks>
    /// <exception cref="InvalidOperationException">The call re-enters ingress from processing or a callback.</exception>
    public void Dispose()
    {
        ThrowIfCalledFromSinkCallback("Message ingress cannot be disposed from a sink callback.");
        if (_isDisposed)
        {
            return;
        }

        if (_isConsuming)
        {
            MarkReentry();
            throw new InvalidOperationException("Message ingress cannot be disposed from a sink callback.");
        }

        _payloadValidator?.Dispose();
        _payloadValidator = null;
        _isDisposed = true;
    }

    private OperationStatus ConsumeHeader(
        ReadOnlySpan<byte> source,
        out int bytesConsumed)
    {
        bytesConsumed = 0;
        var requiredLength = _headerLength < MessageHeaderCodec.BasicHeaderLength
            ? MessageHeaderCodec.BasicHeaderLength
            : MessageHeaderCodec.ExtendedHeaderLength;
        var copiedLength = Math.Min(source.Length, requiredLength - _headerLength);
        source[..copiedLength].CopyTo(_headerBuffer.AsSpan(_headerLength));
        _headerLength += copiedLength;
        bytesConsumed = copiedLength;

        if (_headerLength < requiredLength)
        {
            return OperationStatus.NeedMoreData;
        }

        var parseStatus = MessageHeaderCodec.TryParse(
            _headerBuffer.AsSpan(0, _headerLength),
            _expectedNetworkMagic,
            _maximumPayloadLength,
            out var header,
            out _);
        if (parseStatus == OperationStatus.NeedMoreData)
        {
            var remainingBytesConsumed = 0;
            OperationStatus remainingStatus;
            try
            {
                remainingStatus = ConsumeHeader(
                    source[copiedLength..],
                    out remainingBytesConsumed);
            }
            catch
            {
                bytesConsumed = copiedLength + remainingBytesConsumed;
                throw;
            }

            bytesConsumed = copiedLength + remainingBytesConsumed;
            return remainingStatus;
        }

        if (parseStatus != OperationStatus.Done)
        {
            Fault();
            return OperationStatus.InvalidData;
        }

        if (!IsAdmitted(header))
        {
            Fault();
            return OperationStatus.InvalidData;
        }

        if (_isFaulted)
        {
            Fault();
            return OperationStatus.InvalidData;
        }

        var computeExtendedDoubleSha256 = ShouldComputeDoubleSha256(header);
        if (_isFaulted ||
            MessagePayloadValidator.TryCreate(
                header,
                computeExtendedDoubleSha256,
                out _payloadValidator) != OperationStatus.Done ||
            _payloadValidator is null)
        {
            Fault();
            return OperationStatus.InvalidData;
        }

        _headerLength = 0;
        NotifyStarted(header);
        return OperationStatus.Done;
    }

    private OperationStatus ConsumePayload(
        ReadOnlySpan<byte> source,
        out int bytesConsumed)
    {
        var validator = _payloadValidator!;
        var acceptedLength = (int)Math.Min((ulong)source.Length, validator.RemainingLength);
        var payload = source[..acceptedLength];
        var status = validator.Consume(payload, out bytesConsumed);

        if (bytesConsumed > 0 && NotifyPayload(payload[..bytesConsumed]) != OperationStatus.Done)
        {
            AbortFrameAndNotify();
            return OperationStatus.InvalidData;
        }

        if (status == OperationStatus.NeedMoreData)
        {
            return status;
        }

        if (status == OperationStatus.Done)
        {
            Hash256? payloadDoubleSha256 = null;
            if (validator.TryGetPayloadDoubleSha256(out var payloadHash) == OperationStatus.Done)
            {
                payloadDoubleSha256 = payloadHash;
            }

            validator.Dispose();
            _payloadValidator = null;
            NotifyCompleted(new MessageIngressResult(
                MessageIngressCompletion.FrameValidated,
                payloadDoubleSha256));
            return status;
        }

        AbortFrameAndNotify();
        return OperationStatus.InvalidData;
    }

    private bool IsAdmitted(in MessageHeader header)
    {
        if (_admissionPolicy is null)
        {
            return true;
        }

        try
        {
            _isEvaluatingPolicy = true;
            return _admissionPolicy.IsAdmitted(header);
        }
        catch
        {
            Fault();
            throw;
        }
        finally
        {
            _isEvaluatingPolicy = false;
        }
    }

    private bool ShouldComputeDoubleSha256(in MessageHeader header)
    {
        if (_payloadHashPolicy is null || header.Format != MessageHeaderFormat.Extended)
        {
            return false;
        }

        try
        {
            _isEvaluatingPolicy = true;
            return _payloadHashPolicy.ShouldComputeDoubleSha256(header);
        }
        catch
        {
            Fault();
            throw;
        }
        finally
        {
            _isEvaluatingPolicy = false;
        }
    }

    private void NotifyStarted(in MessageHeader header)
    {
        try
        {
            _isCallingSink = true;
            _sink.OnMessageStarted(header);
        }
        catch
        {
            Fault();
            throw;
        }
        finally
        {
            CompleteSinkCallback();
        }
    }

    private OperationStatus NotifyPayload(ReadOnlySpan<byte> payload)
    {
        try
        {
            _isCallingSink = true;
            return _sink.OnProvisionalPayload(payload);
        }
        catch
        {
            Fault();
            throw;
        }
        finally
        {
            CompleteSinkCallback();
        }
    }

    private void NotifyCompleted(in MessageIngressResult result)
    {
        try
        {
            _isCallingSink = true;
            _sink.OnMessageCompleted(result);
        }
        catch
        {
            Fault();
            throw;
        }
        finally
        {
            CompleteSinkCallback();
        }
    }

    private void AbortFrameAndNotify()
    {
        _payloadValidator?.Dispose();
        _payloadValidator = null;
        _isFaulted = true;
        NotifyCompleted(new MessageIngressResult(MessageIngressCompletion.FrameAborted, null));
    }

    private void MarkReentry()
    {
        if (_isCallingSink)
        {
            _isFaulted = true;
            _sinkCallbackReentryDetected = true;
        }
        else if (_isEvaluatingPolicy)
        {
            _isFaulted = true;
        }
    }

    private void ThrowIfCalledFromSinkCallback(string message)
    {
        if (!_isCallingSink)
        {
            return;
        }

        MarkReentry();
        throw new InvalidOperationException(message);
    }

    private void CompleteSinkCallback()
    {
        _isCallingSink = false;
        if (_sinkCallbackReentryDetected)
        {
            Fault();
            throw new InvalidOperationException(
                "Message ingress reentrancy was caught inside a sink callback.");
        }
    }

    private void Fault()
    {
        _payloadValidator?.Dispose();
        _payloadValidator = null;
        _isFaulted = true;
    }
}
