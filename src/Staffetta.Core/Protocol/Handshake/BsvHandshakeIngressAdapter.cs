using System.Buffers;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Protocol.Handshake;

/// <summary>
/// Adapts validated, bounded BSV control frames to a sans-I/O handshake state machine.
/// </summary>
/// <remarks>
/// Instances are single-consumer and not thread-safe. Payload bytes are provisional until the
/// framing checksum and the command-specific codec both accept the complete frame. Unknown
/// commands are consumed without buffering or handshake effects.
/// </remarks>
public sealed class BsvHandshakeIngressAdapter :
    IMessageIngressSink,
    IMessageIngressAdmissionPolicy,
    IDisposable
{
    public const int MaximumStagedPayloadLength = BsvHandshakeFrameProcessor.MaximumStagedPayloadLength;

    private readonly BsvHandshakeFrameProcessor _processor;
    private readonly MessageIngressStateMachine _ingress;
    private bool _isIngressUnusable;
    private bool _isCompleted;
    private bool _isDisposed;

    public BsvHandshakeIngressAdapter(
        ReadOnlySpan<byte> expectedNetworkMagic,
        ulong maximumPayloadLength,
        int minimumPeerProtocolVersion)
    {
        _processor = new BsvHandshakeFrameProcessor(minimumPeerProtocolVersion);
        _ingress = new MessageIngressStateMachine(
            expectedNetworkMagic,
            maximumPayloadLength,
            this,
            this);
    }

    public BsvHandshakeStateMachine Handshake => _processor.Handshake;

    public int PendingOutputCount => _processor.PendingOutputCount;

    public OperationStatus Start(ulong localNonce)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (_isCompleted ||
            _isIngressUnusable ||
            Handshake.State == BsvHandshakeState.Terminal)
        {
            return OperationStatus.InvalidData;
        }

        return _processor.Start(localNonce);
    }

    /// <summary>Consumes at most one complete wire frame.</summary>
    public OperationStatus Consume(ReadOnlySpan<byte> source, out int bytesConsumed)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        bytesConsumed = 0;
        if (_isCompleted ||
            _isIngressUnusable ||
            Handshake.State is BsvHandshakeState.Created or BsvHandshakeState.Terminal)
        {
            return OperationStatus.InvalidData;
        }

        if (_processor.PendingOutputCount != 0)
        {
            return OperationStatus.DestinationTooSmall;
        }

        _processor.BeginConsume();
        OperationStatus status;
        try
        {
            status = _ingress.ConsumeSingleFrame(source, out bytesConsumed);
        }
        catch
        {
            _isIngressUnusable = true;
            throw;
        }

        if (status == OperationStatus.InvalidData && !_processor.FrameAborted)
        {
            _isIngressUnusable = true;
            _processor.ApplyWireViolation();
        }
        else if (_processor.FrameAborted)
        {
            _isIngressUnusable = true;
        }

        if (_processor.FrameProcessingFailed)
        {
            _isIngressUnusable = true;
            return OperationStatus.InvalidData;
        }

        return status;
    }

    /// <summary>Copies all pending outputs atomically into caller-owned storage.</summary>
    public OperationStatus DrainOutputs(
        Span<BsvHandshakeOutput> destination,
        out int outputsWritten)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        return _processor.DrainOutputs(destination, out outputsWritten);
    }

    public OperationStatus CompleteEndOfInput()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (_isIngressUnusable)
        {
            return OperationStatus.InvalidData;
        }

        if (_isCompleted)
        {
            return OperationStatus.Done;
        }

        _processor.BeginCompleteEndOfInput();
        OperationStatus status;
        try
        {
            status = _ingress.CompleteEndOfInput();
        }
        catch
        {
            _isIngressUnusable = true;
            throw;
        }

        if (status == OperationStatus.InvalidData && !_processor.FrameAborted)
        {
            _isIngressUnusable = true;
            _processor.ApplyWireViolation();
        }
        else if (status == OperationStatus.InvalidData)
        {
            _isIngressUnusable = true;
        }
        else
        {
            _isCompleted = true;
        }

        return status;
    }

    public void Dispose()
    {
        if (_isDisposed)
        {
            return;
        }

        _processor.Dispose();
        _ingress.Dispose();
        _isDisposed = true;
    }

    bool IMessageIngressAdmissionPolicy.IsAdmitted(in MessageHeader header) =>
        BsvHandshakeFrameProcessor.IsAdmitted(header);

    void IMessageIngressSink.OnMessageStarted(in MessageHeader header)
    {
        _processor.OnMessageStarted(header);
    }

    OperationStatus IMessageIngressSink.OnProvisionalPayload(ReadOnlySpan<byte> payload) =>
        _processor.OnProvisionalPayload(payload);

    void IMessageIngressSink.OnMessageCompleted(in MessageIngressResult result)
    {
        _processor.OnMessageCompleted(result);
        if (_processor.FrameProcessingFailed)
        {
            _isIngressUnusable = true;
        }
    }
}
