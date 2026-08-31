using System.Buffers;

namespace Staffetta.Core.Protocol.Wire;

/// <summary>
/// Incrementally frames wire messages without retaining their payloads.
/// </summary>
/// <remarks>
/// Instances are single-consumer and not thread-safe. Sink callbacks made by <see cref="Consume"/>
/// cannot call Consume, <see cref="CompleteEndOfInput"/>, or <see cref="Dispose"/> on the same
/// instance. A malformed frame or an exception from a sink callback permanently faults the
/// instance. Callback exceptions are propagated and the event that caused one is never replayed.
/// </remarks>
public sealed class MessageIngressStateMachine : IDisposable
{
    private readonly byte[] _expectedNetworkMagic;
    private readonly ulong _maximumPayloadLength;
    private readonly IMessageIngressSink _sink;
    private readonly byte[] _headerBuffer = new byte[MessageHeaderCodec.ExtendedHeaderLength];

    private MessagePayloadValidator? _payloadValidator;
    private int _headerLength;
    private bool _isConsuming;
    private bool _isCompleted;
    private bool _isFaulted;
    private bool _isDisposed;

    public MessageIngressStateMachine(
        ReadOnlySpan<byte> expectedNetworkMagic,
        ulong maximumPayloadLength,
        IMessageIngressSink sink)
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
    }

    public bool IsCompleted => _isCompleted;

    public bool IsFaulted => _isFaulted;

    public OperationStatus Consume(
        ReadOnlySpan<byte> source,
        out int bytesConsumed)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        bytesConsumed = 0;
        if (_isConsuming)
        {
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
                    var headerStatus = ConsumeHeader(source[bytesConsumed..], out var headerBytesConsumed);
                    bytesConsumed += headerBytesConsumed;
                    if (headerStatus != OperationStatus.Done)
                    {
                        return headerStatus;
                    }
                }

                var payloadStatus = ConsumePayload(source[bytesConsumed..], out var payloadBytesConsumed);
                bytesConsumed += payloadBytesConsumed;
                if (payloadStatus != OperationStatus.Done)
                {
                    return payloadStatus;
                }

                if (bytesConsumed == source.Length)
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

    public OperationStatus CompleteEndOfInput()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (_isConsuming)
        {
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
            NotifyCompleted(MessageIngressCompletion.FrameAborted);
            return OperationStatus.InvalidData;
        }

        if (_headerLength > 0)
        {
            _isFaulted = true;
            return OperationStatus.InvalidData;
        }

        return OperationStatus.Done;
    }

    public void Dispose()
    {
        if (_isDisposed)
        {
            return;
        }

        if (_isConsuming)
        {
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
            var remainingStatus = ConsumeHeader(
                source[copiedLength..],
                out var remainingBytesConsumed);
            bytesConsumed = copiedLength + remainingBytesConsumed;
            return remainingStatus;
        }

        if (parseStatus != OperationStatus.Done ||
            MessagePayloadValidator.TryCreate(header, out _payloadValidator) != OperationStatus.Done ||
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

        if (bytesConsumed > 0)
        {
            NotifyPayload(payload[..bytesConsumed]);
        }

        if (status == OperationStatus.NeedMoreData)
        {
            return status;
        }

        validator.Dispose();
        _payloadValidator = null;

        if (status == OperationStatus.Done)
        {
            NotifyCompleted(MessageIngressCompletion.FrameValidated);
            return status;
        }

        _isFaulted = true;
        NotifyCompleted(MessageIngressCompletion.FrameAborted);
        return OperationStatus.InvalidData;
    }

    private void NotifyStarted(in MessageHeader header)
    {
        try
        {
            _sink.OnMessageStarted(header);
        }
        catch
        {
            Fault();
            throw;
        }
    }

    private void NotifyPayload(ReadOnlySpan<byte> payload)
    {
        try
        {
            _sink.OnProvisionalPayload(payload);
        }
        catch
        {
            Fault();
            throw;
        }
    }

    private void NotifyCompleted(MessageIngressCompletion completion)
    {
        try
        {
            _sink.OnMessageCompleted(completion);
        }
        catch
        {
            Fault();
            throw;
        }
    }

    private void Fault()
    {
        _payloadValidator?.Dispose();
        _payloadValidator = null;
        _isFaulted = true;
    }
}
