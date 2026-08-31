using System.Buffers;

namespace Staffetta.Core.Protocol.Handshake;

/// <summary>
/// Drives one BSV handshake without performing transport, framing, time, or nonce generation.
/// </summary>
/// <remarks>
/// The caller must pass only fully validated frame payloads. Instances are single-consumer and
/// not thread-safe. Output spans are caller-owned and are never retained.
/// </remarks>
public sealed class BsvHandshakeStateMachine
{
    // The BSV protocol default applies until a valid protoconf advertises a larger limit.
    public const uint DefaultPeerMaximumReceivePayloadLength = 1_048_576;

    public const uint MinimumPeerReceivePayloadLength = DefaultPeerMaximumReceivePayloadLength;

    public const int MaximumOutputCount = 3;

    private readonly int _minimumPeerProtocolVersion;

    private ulong _localNonce;
    private ulong _peerNonce;
    private ulong _pendingPingNonce;
    private uint _peerMaximumReceivePayloadLength;
    private int _peerProtocolVersion;
    private bool _localVersionIntent;
    private bool _localVerackIntent;
    private bool _hasPeerVersion;
    private bool _hasPeerVerack;
    private bool _hasPeerProtoconf;
    private bool _hasPendingPing;

    public BsvHandshakeStateMachine(int minimumPeerProtocolVersion)
    {
        if (minimumPeerProtocolVersion <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(minimumPeerProtocolVersion),
                "Minimum peer protocol version must be positive.");
        }

        _minimumPeerProtocolVersion = minimumPeerProtocolVersion;
    }

    public BsvHandshakeState State { get; private set; }

    public BsvHandshakeTerminalReason TerminalReason { get; private set; }

    public int MinimumPeerProtocolVersion => _minimumPeerProtocolVersion;

    public bool HasPeerVersion => _hasPeerVersion;

    public int PeerProtocolVersion => _peerProtocolVersion;

    public ulong PeerNonce => _peerNonce;

    public bool HasPeerVerack => _hasPeerVerack;

    public bool HasPeerProtoconf => _hasPeerProtoconf;

    public uint AdvertisedPeerMaximumReceivePayloadLength => _peerMaximumReceivePayloadLength;

    public uint EffectivePeerMaximumReceivePayloadLength => _hasPeerProtoconf
        ? _peerMaximumReceivePayloadLength
        : DefaultPeerMaximumReceivePayloadLength;

    public bool HasPendingPing => _hasPendingPing;

    public OperationStatus Start(
        ulong localNonce,
        Span<BsvHandshakeOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (State != BsvHandshakeState.Created)
        {
            return OperationStatus.InvalidData;
        }

        if (destination.IsEmpty)
        {
            return OperationStatus.DestinationTooSmall;
        }

        _localNonce = localNonce;
        _localVersionIntent = true;
        State = BsvHandshakeState.Negotiating;
        destination[0] = new BsvHandshakeOutput(BsvHandshakeOutputKind.SendVersion, localNonce);
        outputsWritten = 1;
        return OperationStatus.Done;
    }

    public OperationStatus Apply(
        BsvHandshakeInput input,
        Span<BsvHandshakeOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (State == BsvHandshakeState.Terminal)
        {
            return OperationStatus.Done;
        }

        if (State == BsvHandshakeState.Created || input.Kind == BsvHandshakeInputKind.None)
        {
            return OperationStatus.InvalidData;
        }

        return input.Kind switch
        {
            BsvHandshakeInputKind.PeerVersion => ApplyPeerVersion(input, destination, out outputsWritten),
            BsvHandshakeInputKind.PeerVerack => ApplyPeerVerack(destination, out outputsWritten),
            BsvHandshakeInputKind.PeerProtoconf => ApplyPeerProtoconf(input),
            BsvHandshakeInputKind.PeerPing => ApplyPeerPing(input.Value, destination, out outputsWritten),
            BsvHandshakeInputKind.PeerPong => ApplyPeerPong(input.Value, destination, out outputsWritten),
            BsvHandshakeInputKind.PeerReject => ApplyPeerReject(destination, out outputsWritten),
            BsvHandshakeInputKind.WireViolation => Terminate(BsvHandshakeTerminalReason.WireViolation),
            BsvHandshakeInputKind.ExternalFailure => Terminate(BsvHandshakeTerminalReason.ExternalFailure),
            _ => OperationStatus.InvalidData,
        };
    }

    public OperationStatus TryBeginPing(
        ulong nonce,
        Span<BsvHandshakeOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (State != BsvHandshakeState.Ready || _hasPendingPing)
        {
            return OperationStatus.InvalidData;
        }

        if (destination.IsEmpty)
        {
            return OperationStatus.DestinationTooSmall;
        }

        _pendingPingNonce = nonce;
        _hasPendingPing = true;
        destination[0] = new BsvHandshakeOutput(BsvHandshakeOutputKind.SendPing, nonce);
        outputsWritten = 1;
        return OperationStatus.Done;
    }

    private OperationStatus ApplyPeerVersion(
        BsvHandshakeInput input,
        Span<BsvHandshakeOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (_hasPeerVersion || State == BsvHandshakeState.Ready)
        {
            return Terminate(BsvHandshakeTerminalReason.DuplicateVersion);
        }

        if (input.Value == _localNonce)
        {
            return Terminate(BsvHandshakeTerminalReason.SelfConnection);
        }

        if (input.ProtocolVersion < _minimumPeerProtocolVersion)
        {
            return Terminate(BsvHandshakeTerminalReason.UnsupportedProtocolVersion);
        }

        var becomesReady = _localVersionIntent && _hasPeerVerack;
        var requiredOutputLength = becomesReady ? 3 : 2;
        if (destination.Length < requiredOutputLength)
        {
            return OperationStatus.DestinationTooSmall;
        }

        _hasPeerVersion = true;
        _peerProtocolVersion = input.ProtocolVersion;
        _peerNonce = input.Value;
        _localVerackIntent = true;
        destination[0] = new BsvHandshakeOutput(BsvHandshakeOutputKind.SendVerack);
        destination[1] = new BsvHandshakeOutput(BsvHandshakeOutputKind.SendProtoconf);
        outputsWritten = 2;

        if (becomesReady)
        {
            State = BsvHandshakeState.Ready;
            destination[2] = new BsvHandshakeOutput(BsvHandshakeOutputKind.BecameReady);
            outputsWritten = 3;
        }

        return OperationStatus.Done;
    }

    private OperationStatus ApplyPeerVerack(
        Span<BsvHandshakeOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (_hasPeerVerack)
        {
            return OperationStatus.Done;
        }

        var becomesReady = _localVersionIntent && _hasPeerVersion && _localVerackIntent;
        if (becomesReady && destination.IsEmpty)
        {
            return OperationStatus.DestinationTooSmall;
        }

        _hasPeerVerack = true;
        if (becomesReady)
        {
            State = BsvHandshakeState.Ready;
            destination[0] = new BsvHandshakeOutput(BsvHandshakeOutputKind.BecameReady);
            outputsWritten = 1;
        }

        return OperationStatus.Done;
    }

    private OperationStatus ApplyPeerProtoconf(BsvHandshakeInput input)
    {
        if (!_hasPeerVersion || !_hasPeerVerack)
        {
            return Terminate(BsvHandshakeTerminalReason.EarlyProtoconf);
        }

        if (_hasPeerProtoconf)
        {
            return Terminate(BsvHandshakeTerminalReason.DuplicateProtoconf);
        }

        if (input.Value < MinimumPeerReceivePayloadLength)
        {
            return Terminate(BsvHandshakeTerminalReason.InsufficientPeerReceiveLimit);
        }

        _hasPeerProtoconf = true;
        _peerMaximumReceivePayloadLength = (uint)input.Value;
        return OperationStatus.Done;
    }

    private static OperationStatus ApplyPeerPing(
        ulong nonce,
        Span<BsvHandshakeOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (destination.IsEmpty)
        {
            return OperationStatus.DestinationTooSmall;
        }

        destination[0] = new BsvHandshakeOutput(BsvHandshakeOutputKind.SendPong, nonce);
        outputsWritten = 1;
        return OperationStatus.Done;
    }

    private OperationStatus ApplyPeerPong(
        ulong nonce,
        Span<BsvHandshakeOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (!_hasPendingPing || nonce != _pendingPingNonce)
        {
            return OperationStatus.Done;
        }

        if (destination.IsEmpty)
        {
            return OperationStatus.DestinationTooSmall;
        }

        _hasPendingPing = false;
        destination[0] = new BsvHandshakeOutput(BsvHandshakeOutputKind.PingAcknowledged, nonce);
        outputsWritten = 1;
        return OperationStatus.Done;
    }

    private OperationStatus ApplyPeerReject(
        Span<BsvHandshakeOutput> destination,
        out int outputsWritten)
    {
        outputsWritten = 0;
        if (State != BsvHandshakeState.Ready)
        {
            return Terminate(BsvHandshakeTerminalReason.RejectBeforeReady);
        }

        if (destination.IsEmpty)
        {
            return OperationStatus.DestinationTooSmall;
        }

        destination[0] = new BsvHandshakeOutput(BsvHandshakeOutputKind.ForwardReject);
        outputsWritten = 1;
        return OperationStatus.Done;
    }

    private OperationStatus Terminate(BsvHandshakeTerminalReason reason)
    {
        State = BsvHandshakeState.Terminal;
        TerminalReason = reason;
        _hasPendingPing = false;
        return OperationStatus.Done;
    }
}
