using System.Buffers;
using Staffetta.Core.Protocol.Messages;
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
    public const int MaximumStagedPayloadLength = VersionPayloadCodec.MaximumPayloadLength;

    private readonly BsvHandshakeOutput[] _pendingOutputs =
        new BsvHandshakeOutput[BsvHandshakeStateMachine.MaximumOutputCount];
    private readonly byte[] _smallPayloadBuffer = new byte[MaximumStagedPayloadLength];
    private readonly MessageIngressStateMachine _ingress;

    private IncrementalProtoconfPayloadParser _protoconfParser;
    private StagedCommand _stagedCommand;
    private int _stagedLength;
    private int _pendingOutputCount;
    private bool _frameAborted;
    private bool _frameProcessingFailed;
    private bool _hasActiveFrame;
    private bool _isIngressUnusable;
    private bool _isCompleted;
    private bool _isDisposed;

    public BsvHandshakeIngressAdapter(
        ReadOnlySpan<byte> expectedNetworkMagic,
        ulong maximumPayloadLength,
        int minimumPeerProtocolVersion)
    {
        Handshake = new BsvHandshakeStateMachine(minimumPeerProtocolVersion);
        _ingress = new MessageIngressStateMachine(
            expectedNetworkMagic,
            maximumPayloadLength,
            this,
            this);
    }

    public BsvHandshakeStateMachine Handshake { get; }

    public int PendingOutputCount => _pendingOutputCount;

    public OperationStatus Start(ulong localNonce)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (_isCompleted ||
            _isIngressUnusable ||
            Handshake.State == BsvHandshakeState.Terminal)
        {
            return OperationStatus.InvalidData;
        }

        if (_pendingOutputCount != 0)
        {
            return OperationStatus.DestinationTooSmall;
        }

        var status = Handshake.Start(localNonce, _pendingOutputs, out var outputsWritten);
        if (status == OperationStatus.Done)
        {
            _pendingOutputCount = outputsWritten;
        }

        return status;
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

        if (_pendingOutputCount != 0)
        {
            return OperationStatus.DestinationTooSmall;
        }

        _frameAborted = false;
        _frameProcessingFailed = false;
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

        if (status == OperationStatus.InvalidData && !_frameAborted)
        {
            _isIngressUnusable = true;
            ApplyTerminal(BsvHandshakeInput.WireViolation());
        }
        else if (_frameAborted)
        {
            _isIngressUnusable = true;
        }

        if (_frameProcessingFailed)
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
        outputsWritten = 0;
        if (destination.Length < _pendingOutputCount)
        {
            return OperationStatus.DestinationTooSmall;
        }

        _pendingOutputs.AsSpan(0, _pendingOutputCount).CopyTo(destination);
        outputsWritten = _pendingOutputCount;
        _pendingOutputs.AsSpan(0, _pendingOutputCount).Clear();
        _pendingOutputCount = 0;
        return OperationStatus.Done;
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

        _frameAborted = false;
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

        if (status == OperationStatus.InvalidData && !_frameAborted)
        {
            _isIngressUnusable = true;
            ApplyTerminal(BsvHandshakeInput.WireViolation());
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

        ResetStagedFrame();
        _pendingOutputs.AsSpan().Clear();
        _pendingOutputCount = 0;
        _ingress.Dispose();
        _isDisposed = true;
    }

    bool IMessageIngressAdmissionPolicy.IsAdmitted(in MessageHeader header) =>
        Classify(header.Command) switch
        {
            StagedCommand.Version => header.PayloadLength is >= VersionPayloadCodec.RequiredPrefixLength
                and <= MaximumStagedPayloadLength,
            StagedCommand.Verack => header.PayloadLength == 0,
            StagedCommand.Ping or StagedCommand.Pong =>
                header.PayloadLength == ModernPingPongPayloadCodec.EncodedLength,
            StagedCommand.Reject => header.PayloadLength is >= 3
                and <= RejectPayloadCodec.MaximumPayloadLength,
            StagedCommand.Protoconf => header.PayloadLength is >= 5
                and <= ProtoconfPayloadCodec.MaximumPayloadLength,
            _ => true,
        };

    void IMessageIngressSink.OnMessageStarted(in MessageHeader header)
    {
        ResetStagedFrame();
        _hasActiveFrame = true;
        _stagedCommand = Classify(header.Command);
        if (_stagedCommand == StagedCommand.Protoconf)
        {
            _protoconfParser.Reset();
        }
    }

    void IMessageIngressSink.OnProvisionalPayload(ReadOnlySpan<byte> payload)
    {
        switch (_stagedCommand)
        {
            case StagedCommand.Version:
            case StagedCommand.Verack:
            case StagedCommand.Ping:
            case StagedCommand.Pong:
            case StagedCommand.Reject:
                payload.CopyTo(_smallPayloadBuffer.AsSpan(_stagedLength));
                _stagedLength += payload.Length;
                break;
            case StagedCommand.Protoconf:
                _protoconfParser.Consume(payload);
                break;
        }
    }

    void IMessageIngressSink.OnMessageCompleted(in MessageIngressResult result)
    {
        if (!_hasActiveFrame)
        {
            _frameProcessingFailed = true;
            _isIngressUnusable = true;
            return;
        }

        if (result.Completion == MessageIngressCompletion.FrameAborted)
        {
            _frameAborted = true;
            ResetStagedFrame();
            return;
        }

        var inputStatus = TryCreateInput(out var input);
        ResetStagedFrame();
        if (inputStatus == OperationStatus.Done && input.Kind != BsvHandshakeInputKind.None)
        {
            ApplyInput(input);
        }
        else if (inputStatus != OperationStatus.Done)
        {
            _frameProcessingFailed = true;
            ApplyTerminal(BsvHandshakeInput.WireViolation());
        }
    }

    private OperationStatus TryCreateInput(out BsvHandshakeInput input)
    {
        input = default;
        var payload = _smallPayloadBuffer.AsSpan(0, _stagedLength);
        switch (_stagedCommand)
        {
            case StagedCommand.Version:
                var versionStatus = VersionPayloadCodec.TryParse(
                    payload,
                    out var version,
                    out var versionBytesConsumed);
                if (versionStatus == OperationStatus.Done && versionBytesConsumed == payload.Length)
                {
                    input = BsvHandshakeInput.PeerVersion(version.ProtocolVersion, version.Nonce);
                }

                return versionStatus == OperationStatus.Done && versionBytesConsumed != payload.Length
                    ? OperationStatus.InvalidData
                    : versionStatus;

            case StagedCommand.Verack:
                var verackStatus = VerackPayloadCodec.TryParse(payload);
                if (verackStatus == OperationStatus.Done)
                {
                    input = BsvHandshakeInput.PeerVerack();
                }

                return verackStatus;

            case StagedCommand.Ping:
                var pingStatus = ModernPingPongPayloadCodec.TryParse(payload, out var pingNonce);
                if (pingStatus == OperationStatus.Done)
                {
                    input = BsvHandshakeInput.PeerPing(pingNonce);
                }

                return pingStatus;

            case StagedCommand.Pong:
                var pongStatus = ModernPingPongPayloadCodec.TryParse(payload, out var pongNonce);
                if (pongStatus == OperationStatus.Done)
                {
                    input = BsvHandshakeInput.PeerPong(pongNonce);
                }

                return pongStatus;

            case StagedCommand.Reject:
                var rejectStatus = RejectPayloadCodec.TryParse(
                    payload,
                    out _,
                    out var rejectBytesConsumed);
                if (rejectStatus == OperationStatus.Done && rejectBytesConsumed == payload.Length)
                {
                    input = BsvHandshakeInput.PeerReject();
                }

                return rejectStatus == OperationStatus.Done && rejectBytesConsumed != payload.Length
                    ? OperationStatus.InvalidData
                    : rejectStatus;

            case StagedCommand.Protoconf:
                var protoconfStatus = _protoconfParser.Complete(out var receiveLimit);
                if (protoconfStatus == OperationStatus.Done)
                {
                    input = BsvHandshakeInput.PeerProtoconf(receiveLimit);
                }

                return protoconfStatus;

            default:
                return OperationStatus.Done;
        }
    }

    private void ApplyInput(BsvHandshakeInput input)
    {
        var status = Handshake.Apply(input, _pendingOutputs, out var outputsWritten);
        if (status == OperationStatus.Done)
        {
            _pendingOutputCount = outputsWritten;
            return;
        }

        _frameProcessingFailed = true;
        ApplyTerminal(BsvHandshakeInput.ExternalFailure());
    }

    private void ApplyTerminal(BsvHandshakeInput input)
    {
        _pendingOutputs.AsSpan().Clear();
        _pendingOutputCount = 0;
        var status = Handshake.Apply(input, _pendingOutputs, out var outputsWritten);
        if (status == OperationStatus.Done)
        {
            _pendingOutputCount = outputsWritten;
        }
    }

    private void ResetStagedFrame()
    {
        _smallPayloadBuffer.AsSpan(0, _stagedLength).Clear();
        _stagedLength = 0;
        _stagedCommand = StagedCommand.Unknown;
        _protoconfParser.Reset();
        _hasActiveFrame = false;
    }

    private static StagedCommand Classify(in MessageCommand command)
    {
        if (command.Equals("version"u8))
        {
            return StagedCommand.Version;
        }

        if (command.Equals("verack"u8))
        {
            return StagedCommand.Verack;
        }

        if (command.Equals("ping"u8))
        {
            return StagedCommand.Ping;
        }

        if (command.Equals("pong"u8))
        {
            return StagedCommand.Pong;
        }

        if (command.Equals("reject"u8))
        {
            return StagedCommand.Reject;
        }

        return command.Equals("protoconf"u8)
            ? StagedCommand.Protoconf
            : StagedCommand.Unknown;
    }

    private enum StagedCommand
    {
        Unknown,
        Version,
        Verack,
        Ping,
        Pong,
        Reject,
        Protoconf,
    }
}
