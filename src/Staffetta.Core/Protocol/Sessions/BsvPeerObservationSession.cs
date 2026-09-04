using System.Buffers;
using System.Buffers.Binary;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Encoding;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Messages;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Protocol.Sessions;

/// <summary>An opaque, exact pending write range owned by one observation session.</summary>
/// <remarks>Bytes remain valid only until acknowledgement or disposal. Acknowledge only bytes actually written; stale, foreign, default, and over-length acknowledgements fault the session.</remarks>
public readonly struct BsvPeerWriteLease
{
    internal BsvPeerWriteLease(MessageFrameWriteSegment segment) => Segment = segment;
    internal MessageFrameWriteSegment Segment { get; }
    /// <summary>Gets the borrowed bytes to write without modification.</summary>
    public ReadOnlyMemory<byte> Bytes => Segment.Memory;
}

/// <summary>A transport-free, single-peer BSV observation driver with validated inventory, notfound and headers and streaming transactions.</summary>
/// <remarks>
/// Single-consumer and not thread-safe; callbacks must not re-enter this instance. The caller owns
/// sockets, timeouts, scheduling, persistence, and transaction staging. Drain validated observations
/// before consuming another frame and write all leases before reading again. Transaction commit
/// checks framing, serialization and monetary range, not scripts, input existence, or mining validity.
/// Buffers are allocated from explicit constructor limits, never peer-declared sizes. Headers are
/// serialization-validated only; contextual admission belongs to <see cref="BsvSelectedHeaderChain"/>.
/// This driver does not broadcast, manage peers, retry requests, correlate notfound, or claim propagation.
/// </remarks>
public sealed class BsvPeerObservationSession : IDisposable
{
    private readonly BsvPeerSessionIngressAdapter _session;
    private readonly BsvPeerObservationBuffers _observations;
    private readonly MessageFrameWriteAuthority _commandWriter = new();
    private readonly byte[] _magic;
    private readonly byte[] _commandPayload = new byte[4 + 3 + 101 * Hash256.Length + Hash256.Length];
    private readonly BsvHandshakeOutput[] _handshakeOutputs = new BsvHandshakeOutput[BsvHandshakeStateMachine.MaximumOutputCount];
    private uint _localMaximumReceivePayloadLength;
    private int _handshakeIndex;
    private int _handshakeCount;
    private int _commandPayloadLength;
    private int _protocolVersion;
    private bool _isConsuming;
    private bool _faulted;
    private bool _disposed;

    /// <summary>Creates a session with explicit frame and bounded control-record admission limits.</summary>
    public BsvPeerObservationSession(ReadOnlySpan<byte> networkMagic, ulong maximumPayloadLength,
        int minimumPeerProtocolVersion, ILegacyTransactionSink transactionSink,
        int maximumInventoryCount = 50_000, int maximumHeaderCount = 2_000)
    {
        _observations = new BsvPeerObservationBuffers(maximumInventoryCount, maximumHeaderCount);
        _session = new BsvPeerSessionIngressAdapter(networkMagic, maximumPayloadLength,
            minimumPeerProtocolVersion, transactionSink, _observations);
        _magic = networkMagic.ToArray();
    }

    /// <summary>Gets the protocol handshake state without performing I/O.</summary>
    public BsvHandshakeState HandshakeState => _session.HandshakeState;
    /// <summary>Gets whether a complete validated inv message awaits drainage, including an empty message; excludes notfound.</summary>
    public bool HasPendingInventory => _observations.HasPendingInventory;
    /// <summary>Gets the number of validated inv records awaiting drainage; excludes notfound.</summary>
    public int PendingInventoryCount => _observations.PendingInventoryCount;
    /// <summary>Gets whether a complete validated notfound message awaits drainage, including an empty message.</summary>
    public bool HasPendingNotFound => _observations.HasPendingNotFound;
    /// <summary>Gets the number of validated notfound records awaiting drainage, without filtering or request correlation.</summary>
    public int PendingNotFoundCount => _observations.PendingNotFoundCount;
    /// <summary>Gets whether a complete validated headers message awaits drainage, including an empty message.</summary>
    public bool HasPendingHeaders => _observations.HasPendingHeaders;
    /// <summary>Gets the number of validated headers awaiting drainage.</summary>
    public int PendingHeaderCount => _observations.PendingHeaderCount;
    /// <summary>Gets the number of monetary rejection verdicts awaiting drainage (at most one).</summary>
    public int PendingMonetaryValidationCount => _session.PendingMonetaryValidationCount;

    /// <summary>Begins the handshake and prepares the local version write; timestamp and nonce are caller-supplied.</summary>
    /// <returns>Done on acceptance, or InvalidData for invalid local configuration or lifecycle.</returns>
    public OperationStatus StartHandshake(VersionPayload localVersion, uint localMaximumReceivePayloadLength)
    {
        CheckAvailable();
        if (localMaximumReceivePayloadLength < 1_048_576 || _session.StartHandshake(localVersion.Nonce) != OperationStatus.Done)
        {
            return OperationStatus.InvalidData;
        }

        _localMaximumReceivePayloadLength = localMaximumReceivePayloadLength;
        _protocolVersion = localVersion.ProtocolVersion;
        if (_session.DrainHandshakeOutputs(_handshakeOutputs, out _) != OperationStatus.Done ||
            _session.PlanVersionEgress(localVersion) != OperationStatus.Done)
        {
            return Fault();
        }

        return OperationStatus.Done;
    }

    /// <summary>Consumes at most one frame; transaction callbacks are provisional until their commit callback.</summary>
    /// <returns>Done, NeedMoreData, DestinationTooSmall while observations or writes remain, or InvalidData on terminal failure.</returns>
    public OperationStatus Consume(ReadOnlySpan<byte> bytes, out int bytesConsumed)
    {
        CheckAvailable();
        bytesConsumed = 0;
        if (_observations.HasPending || TryGetWrite(out _))
        {
            return OperationStatus.DestinationTooSmall;
        }

        _isConsuming = true;
        try
        {
            var status = _session.Consume(bytes, out bytesConsumed);
            if (status == OperationStatus.InvalidData || _faulted)
            {
                return Fault();
            }

            return status;
        }
        catch
        {
            _ = Fault();
            throw;
        }
        finally
        {
            _isConsuming = false;
        }
    }

    /// <summary>Gets the next exact pending write, preparing handshake responses as necessary.</summary>
    /// <returns>True when a lease is available; false when no write is pending.</returns>
    public bool TryGetWrite(out BsvPeerWriteLease lease)
    {
        CheckAvailable();
        if (_commandWriter.Phase != MessageFrameWritePhase.Idle)
        {
            lease = new BsvPeerWriteLease(_commandWriter.PendingSegment);
            return !lease.Bytes.IsEmpty;
        }

        if (_session.EgressState == BsvPeerSessionEgressState.Idle)
        {
            if (_handshakeIndex == _handshakeCount)
            {
                _handshakeIndex = 0;
                if (_session.DrainHandshakeOutputs(_handshakeOutputs, out _handshakeCount) != OperationStatus.Done)
                {
                    throw FaultException();
                }
            }

            while (_handshakeIndex < _handshakeCount)
            {
                var output = _handshakeOutputs[_handshakeIndex++];
                if (output.Kind is BsvHandshakeOutputKind.BecameReady or BsvHandshakeOutputKind.PingAcknowledged or BsvHandshakeOutputKind.ForwardReject)
                {
                    continue;
                }

                var status = output.Kind == BsvHandshakeOutputKind.SendProtoconf
                    ? _session.PlanProtoconfEgress(_localMaximumReceivePayloadLength, [], false)
                    : _session.PlanNextHandshakeEgress();
                if (status != OperationStatus.Done)
                {
                    throw FaultException();
                }

                break;
            }
        }

        lease = new BsvPeerWriteLease(_session.PendingEgressSegment);
        return !lease.Bytes.IsEmpty;
    }

    /// <summary>Acknowledges a positive prefix actually written from the exact current lease.</summary>
    /// <returns>Done on acceptance; InvalidData permanently faults the session without manufacturing a write fact.</returns>
    public OperationStatus AcknowledgeWrite(in BsvPeerWriteLease lease, int bytesWritten)
    {
        CheckAvailable();
        if (_commandWriter.Phase != MessageFrameWritePhase.Idle)
        {
            if (_commandWriter.Acknowledge(lease.Segment, bytesWritten) != OperationStatus.Done)
            {
                return Fault();
            }

            if (_commandWriter.Phase == MessageFrameWritePhase.AwaitingPayload &&
                _commandWriter.ProvidePayloadChunk(_commandPayload.AsMemory(0, _commandPayloadLength)) != OperationStatus.Done)
            {
                return Fault();
            }

            if (_commandWriter.IsComplete)
            {
                _ = _commandWriter.Reset();
            }

            return OperationStatus.Done;
        }

        if (_session.AcknowledgeEgress(lease.Segment, bytesWritten) != OperationStatus.Done ||
            (_session.EgressState == BsvPeerSessionEgressState.Complete &&
                _session.CommitEgressCompletion() != OperationStatus.Done))
        {
            return Fault();
        }

        return OperationStatus.Done;
    }

    /// <summary>Requests one transaction by explicit command intent; no peer inventory or delivery fact is fabricated.</summary>
    /// <returns>Done when queued, DestinationTooSmall while another write remains, otherwise InvalidData.</returns>
    public OperationStatus RequestTransaction(Hash256 transactionId)
    {
        var status = CanRequest();
        if (status != OperationStatus.Done)
        {
            return status;
        }

        Span<InventoryVector> vectors = stackalloc InventoryVector[1];
        vectors[0] = new InventoryVector(1, transactionId);
        _ = InventoryPayloadCodec.TryWrite(vectors, _commandPayload, (ulong)_commandPayload.Length, out _commandPayloadLength);
        return StartCommand("getdata"u8);
    }

    /// <summary>Requests headers using one to 101 caller-selected locator hashes and a stop hash.</summary>
    /// <returns>Done when queued, DestinationTooSmall while another write remains, otherwise InvalidData.</returns>
    public OperationStatus RequestHeaders(ReadOnlySpan<Hash256> locator, Hash256 stopHash = default)
    {
        var status = CanRequest();
        if (status != OperationStatus.Done)
        {
            return status;
        }

        if (locator.Length is < 1 or > 101)
        {
            return OperationStatus.InvalidData;
        }

        BinaryPrimitives.WriteInt32LittleEndian(_commandPayload, _protocolVersion);
        _ = CompactSize.Write((ulong)locator.Length, _commandPayload.AsSpan(4), out var countLength);
        var offset = 4 + countLength;
        foreach (var hash in locator)
        {
            _ = hash.TryCopyWireBytesTo(_commandPayload.AsSpan(offset), out _);
            offset += Hash256.Length;
        }

        _ = stopHash.TryCopyWireBytesTo(_commandPayload.AsSpan(offset), out _);
        _commandPayloadLength = offset + Hash256.Length;
        return StartCommand("getheaders"u8);
    }

    /// <summary>Copies the entire validated inv batch, excluding notfound; insufficient destination leaves it pending.</summary>
    public OperationStatus DrainInventory(Span<InventoryVector> destination, out int count)
    {
        CheckAvailable();
        return _observations.DrainInventory(destination, out count);
    }

    /// <summary>Copies the entire validated notfound batch; insufficient destination leaves it pending.</summary>
    /// <remarks>All vector types are preserved. This is peer-reported evidence, not a correlated request outcome or proof of network absence. Shares the constructor's maximumInventoryCount bound with inv; either pending batch blocks further intake.</remarks>
    /// <returns>Done with zero records when no notfound is pending, or DestinationTooSmall with zero records and no change to the pending batch.</returns>
    public OperationStatus DrainNotFound(Span<InventoryVector> destination, out int count)
    {
        CheckAvailable();
        return _observations.DrainNotFound(destination, out count);
    }

    /// <summary>Copies the entire serialization-validated headers batch; this does not establish consensus validity.</summary>
    public OperationStatus DrainHeaders(Span<BlockHeader> destination, out int count)
    {
        CheckAvailable();
        return _observations.DrainHeaders(destination, out count);
    }

    /// <summary>Drains frame-validated monetary rejection evidence; the corresponding transaction sink lifecycle was aborted, not committed.</summary>
    /// <remarks>Rejected monetary verdicts block subsequent intake until drained. A successful sink commit implies monetary range success, not script or consensus validity.</remarks>
    public OperationStatus DrainMonetaryValidations(Span<BsvTransactionMonetaryValidation> destination, out int count)
    {
        CheckAvailable();
        return _session.DrainMonetaryValidations(destination, out count);
    }

    /// <summary>Reports transport EOF, rejecting incomplete input and releasing provisional state.</summary>
    public OperationStatus CompleteEndOfInput()
    {
        CheckAvailable();
        if (TryGetWrite(out _) || _observations.HasPending || PendingMonetaryValidationCount != 0)
        {
            return OperationStatus.DestinationTooSmall;
        }

        var status = _session.CompleteEndOfInput();
        _faulted = true;
        return status;
    }

    /// <summary>Releases protocol state and pending borrowed write ranges; performs no transport operation.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (_isConsuming)
        {
            throw FaultException();
        }

        _session.Dispose();
        _commandWriter.Dispose();
        _observations.Discard();
        _disposed = true;
    }

    private OperationStatus CanRequest()
    {
        CheckAvailable();
        if (TryGetWrite(out _))
        {
            return OperationStatus.DestinationTooSmall;
        }

        return HandshakeState == BsvHandshakeState.Ready ? OperationStatus.Done : OperationStatus.InvalidData;
    }

    private OperationStatus StartCommand(ReadOnlySpan<byte> command)
    {
        Span<byte> checksum = stackalloc byte[MessageChecksum.Length];
        _ = MessageChecksum.Compute(_commandPayload.AsSpan(0, _commandPayloadLength)).TryCopyTo(checksum, out _);
        _ = MessageHeader.TryCreateBasic(command, (uint)_commandPayloadLength, checksum, out var header);
        return _commandWriter.Start(_magic, header, _session.EffectivePeerMaximumReceivePayloadLength) == OperationStatus.Done
            ? OperationStatus.Done : Fault();
    }

    private void CheckAvailable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_faulted || _isConsuming)
        {
            throw FaultException();
        }
    }

    private OperationStatus Fault()
    {
        _faulted = true;
        _observations.Discard();
        return OperationStatus.InvalidData;
    }

    private InvalidOperationException FaultException()
    {
        _ = Fault();
        if (_isConsuming)
        {
            _session.RejectCallbackReentry();
        }

        return new InvalidOperationException("Observation session is faulted or was re-entered from a callback.");
    }
}
