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
    /// <summary>The effective receive limit in bytes until a valid peer protoconf is accepted.</summary>
    public const uint DefaultPeerMaximumReceivePayloadLength = 1_048_576;

    /// <summary>The minimum acceptable receive limit advertised by peer protoconf, in bytes.</summary>
    public const uint MinimumPeerReceivePayloadLength = DefaultPeerMaximumReceivePayloadLength;

    /// <summary>The maximum number of outputs produced by a single transition.</summary>
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

    /// <summary>Creates a handshake using the caller-selected minimum acceptable peer version.</summary>
    /// <param name="minimumPeerProtocolVersion">A positive protocol version chosen by the caller or profile.</param>
    /// <exception cref="ArgumentOutOfRangeException">The minimum version is not positive.</exception>
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

    /// <summary>Gets the current handshake phase; readiness reflects accepted peer events and local send intents.</summary>
    public BsvHandshakeState State { get; private set; }

    /// <summary>Gets the stable terminal reason, or None before termination.</summary>
    public BsvHandshakeTerminalReason TerminalReason { get; private set; }

    /// <summary>Gets the caller-selected minimum acceptable peer version.</summary>
    public int MinimumPeerProtocolVersion => _minimumPeerProtocolVersion;

    /// <summary>Gets whether a peer version was accepted.</summary>
    public bool HasPeerVersion => _hasPeerVersion;

    /// <summary>Gets the accepted peer version, or zero until HasPeerVersion is true.</summary>
    public int PeerProtocolVersion => _peerProtocolVersion;

    /// <summary>Gets the accepted peer nonce, or zero until HasPeerVersion is true.</summary>
    public ulong PeerNonce => _peerNonce;

    /// <summary>Gets whether a peer verack was accepted, including one received before version.</summary>
    public bool HasPeerVerack => _hasPeerVerack;

    /// <summary>Gets whether a timely, valid peer protoconf was accepted.</summary>
    public bool HasPeerProtoconf => _hasPeerProtoconf;

    /// <summary>Gets the accepted advertised receive limit, or zero until HasPeerProtoconf is true.</summary>
    public uint AdvertisedPeerMaximumReceivePayloadLength => _peerMaximumReceivePayloadLength;

    /// <summary>Gets the accepted advertised receive limit or the protocol default when no protoconf was accepted.</summary>
    public uint EffectivePeerMaximumReceivePayloadLength => _hasPeerProtoconf
        ? _peerMaximumReceivePayloadLength
        : DefaultPeerMaximumReceivePayloadLength;

    /// <summary>Gets whether a local ping intent awaits a matching validated pong; not proof that the ping was written.</summary>
    public bool HasPendingPing => _hasPendingPing;

    /// <summary>Starts negotiation once and emits the local version intent.</summary>
    /// <param name="localNonce">The caller-generated nonce used for self-connection detection.</param>
    /// <param name="destination">Caller-owned output storage; not retained.</param>
    /// <param name="outputsWritten">One on success; otherwise zero.</param>
    /// <returns>Done, InvalidData if already started, or DestinationTooSmall if no output slot is available. Non-success changes neither state nor destination.</returns>
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

    /// <summary>Applies one validated peer event or caller-reported failure and emits its outputs atomically.</summary>
    /// <param name="input">The event to process; the caller must validate peer data before constructing it.</param>
    /// <param name="destination">Caller-owned output storage; not retained. BsvHandshakeStateMachine.MaximumOutputCount slots suffice.</param>
    /// <param name="outputsWritten">The emitted output count, or zero if no output is produced or the call fails.</param>
    /// <returns>Done for an accepted or ignored event; InvalidData for invalid call state or input; DestinationTooSmall without state or destination changes so the same event can be retried.</returns>
    /// <remarks>Terminal state ignores all further inputs and returns Done. Protocol violations may return Done while changing State to Terminal; inspect State and TerminalReason. Send outputs remain intents, not committed transport facts.</remarks>
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

    /// <summary>Emits one local ping intent while ready, allowing only one outstanding nonce.</summary>
    /// <param name="nonce">The caller-generated nonce to match against a validated pong.</param>
    /// <param name="destination">Caller-owned storage for one output; not retained.</param>
    /// <param name="outputsWritten">One on success; otherwise zero.</param>
    /// <returns>Done, InvalidData when not ready or a ping is pending, or DestinationTooSmall. Non-success changes neither state nor destination.</returns>
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
