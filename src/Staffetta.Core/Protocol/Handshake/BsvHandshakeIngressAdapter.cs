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
    /// <summary>The maximum byte count staged for bounded control payloads; protoconf is parsed incrementally.</summary>
    public const int MaximumStagedPayloadLength = BsvHandshakeFrameProcessor.MaximumStagedPayloadLength;

    private readonly BsvHandshakeFrameProcessor _processor;
    private readonly MessageIngressStateMachine _ingress;
    private bool _isIngressUnusable;
    private bool _isCompleted;
    private bool _isDisposed;

    /// <summary>Creates bounded handshake ingress using caller-selected network, size, and version limits.</summary>
    /// <param name="expectedNetworkMagic">Exactly four magic bytes, copied during construction.</param>
    /// <param name="maximumPayloadLength">The inclusive frame payload-length limit, including unknown commands.</param>
    /// <param name="minimumPeerProtocolVersion">A positive minimum acceptable peer version.</param>
    /// <exception cref="ArgumentException">Network magic does not contain exactly four bytes.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The minimum peer version is not positive.</exception>
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

    /// <summary>Gets the adapter-owned handshake state machine for inspecting accepted protocol state.</summary>
    /// <remarks>Direct transitions bypass the adapter's output queue; the caller must coordinate them with adapter use.</remarks>
    public BsvHandshakeStateMachine Handshake => _processor.Handshake;

    /// <summary>Gets the queued output count that must be drained before consuming more input.</summary>
    public int PendingOutputCount => _processor.PendingOutputCount;

    /// <summary>Starts negotiation and queues the local version send intent.</summary>
    /// <param name="localNonce">The caller-generated nonce used for self-connection detection.</param>
    /// <returns>Done on successful start, DestinationTooSmall while outputs remain queued, or InvalidData when start is no longer permitted.</returns>
    /// <exception cref="ObjectDisposedException">The adapter has been disposed.</exception>
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
    /// <param name="source">Caller-owned bytes; bounded control bytes may be copied, but no source span is retained.</param>
    /// <param name="bytesConsumed">Bytes accepted from this call, including bytes accepted before a failure; following frames are untouched.</param>
    /// <returns>Done after one frame, NeedMoreData for an incomplete frame, DestinationTooSmall with zero consumption while outputs await draining, or InvalidData when unusable or not started.</returns>
    /// <remarks>Malformed framing or control payloads permanently prevent further consumption. A completed frame can also cause a terminal handshake transition; inspect Handshake.State. Send outputs are intents, not committed writes.</remarks>
    /// <exception cref="ObjectDisposedException">The adapter has been disposed.</exception>
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
    /// <param name="destination">Storage for the entire pending output queue; not retained.</param>
    /// <param name="outputsWritten">The number drained on success; otherwise zero.</param>
    /// <returns>Done after draining, including an empty queue, or DestinationTooSmall without changing the queue or destination.</returns>
    /// <exception cref="ObjectDisposedException">The adapter has been disposed.</exception>
    public OperationStatus DrainOutputs(
        Span<BsvHandshakeOutput> destination,
        out int outputsWritten)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        return _processor.DrainOutputs(destination, out outputsWritten);
    }

    /// <summary>Declares end of input and checks for an incomplete header or payload without implying handshake readiness.</summary>
    /// <returns>Done at a clean frame boundary, including repeated clean completion; InvalidData for truncation or unusable ingress.</returns>
    /// <remarks>Successful completion prevents future consumption but leaves queued outputs available to drain.</remarks>
    /// <exception cref="ObjectDisposedException">The adapter has been disposed.</exception>
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

    /// <summary>Releases parser and framing resources without reporting end of input; repeated disposal is harmless.</summary>
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
