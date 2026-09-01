using System.Buffers;
using System.Security.Cryptography;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Messages;
using Staffetta.Core.Protocol.Relay;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Protocol.Sessions;

internal enum BsvPeerSessionSendKind
{
    None,
    Version,
    Verack,
    Protoconf,
    Pong,
    Ping,
    Inventory,
    Transaction,
    GetData,
}

internal enum BsvPeerSessionRelayWriteCommitKind
{
    None,
    Inventory,
    Transaction,
    GetData,
}

internal enum BsvPeerSessionOutputDisposition
{
    Send,
    Fact,
}

internal enum BsvPeerSessionEgressState
{
    Idle,
    Active,
    Complete,
    Aborted,
    Faulted,
    Disposed,
}

internal readonly record struct BsvPeerSessionEgressCompletion(
    ulong PlanId,
    BsvPeerSessionSendKind SendKind,
    BsvPeerSessionRelayWriteCommitKind RelayWriteCommitKind,
    Hash256 TransactionId,
    ulong Value);

/// <summary>
/// Maps one peer-session send intent at a time to exact leased frame segments. Transaction chunks
/// remain caller-owned until their current lease is acknowledged.
/// </summary>
internal sealed class BsvPeerSessionEgressPlanner : IDisposable
{
    internal const int MaximumFixedPayloadLength = 658;

    private readonly MessageFrameWriteAuthority _writer = new();
    private readonly byte[] _networkMagic = new byte[MessageHeaderCodec.NetworkMagicLength];
    private readonly byte[] _fixedPayload = new byte[MaximumFixedPayloadLength];

    private IncrementalHash? _transactionHash;
    private BsvPeerSessionEgressState _state;
    private BsvPeerSessionSendKind _sendKind;
    private BsvPeerSessionRelayWriteCommitKind _relayWriteCommitKind;
    private Hash256 _transactionId;
    private ulong _value;
    private int _fixedPayloadLength;
    private BsvPeerSessionEgressCompletion _completion;
    private bool _completionConsumed;
    private ulong _nextPlanId = 1;
    private ulong _planId;

    internal BsvPeerSessionEgressPlanner(ReadOnlySpan<byte> networkMagic)
    {
        if (networkMagic.Length != MessageHeaderCodec.NetworkMagicLength)
        {
            throw new ArgumentException("Network magic must contain exactly four bytes.", nameof(networkMagic));
        }

        networkMagic.CopyTo(_networkMagic);
    }

    internal BsvPeerSessionEgressState State => _state;

    internal MessageFrameWriteSegment PendingSegment => _writer.PendingSegment;

    internal bool TryConsumeCompletion(out BsvPeerSessionEgressCompletion completion)
    {
        if (_state != BsvPeerSessionEgressState.Complete || _completionConsumed)
        {
            completion = default;
            return false;
        }

        completion = _completion;
        _completion = default;
        _completionConsumed = true;
        return true;
    }

    internal OperationStatus PlanHandshake(
        in BsvHandshakeOutput output,
        ulong maximumOutboundPayloadLength,
        out BsvPeerSessionOutputDisposition disposition)
    {
        disposition = BsvPeerSessionOutputDisposition.Send;
        if (!EnsureIdle())
        {
            return Fault();
        }

        switch (output.Kind)
        {
            case BsvHandshakeOutputKind.SendVerack:
                if (output.Value != 0)
                {
                    return Fault();
                }

                return StartFixed(
                    BsvPeerSessionSendKind.Verack,
                    "verack"u8,
                    0,
                    output.Value,
                    maximumOutboundPayloadLength);
            case BsvHandshakeOutputKind.SendPong:
                _ = ModernPingPongPayloadCodec.TryWrite(
                    _fixedPayload,
                    output.Value,
                    out _fixedPayloadLength);
                return StartFixed(
                    BsvPeerSessionSendKind.Pong,
                    "pong"u8,
                    _fixedPayloadLength,
                    output.Value,
                    maximumOutboundPayloadLength);
            case BsvHandshakeOutputKind.SendPing:
                _ = ModernPingPongPayloadCodec.TryWrite(
                    _fixedPayload,
                    output.Value,
                    out _fixedPayloadLength);
                return StartFixed(
                    BsvPeerSessionSendKind.Ping,
                    "ping"u8,
                    _fixedPayloadLength,
                    output.Value,
                    maximumOutboundPayloadLength);
            case BsvHandshakeOutputKind.BecameReady:
            case BsvHandshakeOutputKind.PingAcknowledged:
            case BsvHandshakeOutputKind.ForwardReject:
                disposition = BsvPeerSessionOutputDisposition.Fact;
                return OperationStatus.Done;
            case BsvHandshakeOutputKind.SendVersion:
            case BsvHandshakeOutputKind.SendProtoconf:
            default:
                return Fault();
        }
    }

    internal OperationStatus PlanVersion(
        in BsvHandshakeOutput output,
        VersionPayload payload,
        ulong maximumOutboundPayloadLength)
    {
        if (!EnsureIdle() ||
            output.Kind != BsvHandshakeOutputKind.SendVersion ||
            output.Value != payload.Nonce)
        {
            return Fault();
        }

        var status = VersionPayloadCodec.TryWrite(_fixedPayload, payload, out _fixedPayloadLength);
        return status == OperationStatus.Done
            ? StartFixed(
                BsvPeerSessionSendKind.Version,
                "version"u8,
                _fixedPayloadLength,
                output.Value,
                maximumOutboundPayloadLength)
            : Fault();
    }

    internal OperationStatus PlanProtoconf(
        in BsvHandshakeOutput output,
        uint maximumReceivePayloadLength,
        ReadOnlySpan<byte> streamPolicies,
        bool includeStreamPolicies,
        ulong maximumOutboundPayloadLength)
    {
        if (!EnsureIdle() ||
            output.Kind != BsvHandshakeOutputKind.SendProtoconf ||
            output.Value != 0)
        {
            return Fault();
        }

        var status = ProtoconfPayloadCodec.TryWrite(
            _fixedPayload,
            maximumReceivePayloadLength,
            streamPolicies,
            includeStreamPolicies,
            out _fixedPayloadLength);
        return status == OperationStatus.Done
            ? StartFixed(
                BsvPeerSessionSendKind.Protoconf,
                "protoconf"u8,
                _fixedPayloadLength,
                output.Value,
                maximumOutboundPayloadLength)
            : Fault();
    }

    internal OperationStatus PlanBroadcast(
        in BsvTransactionBroadcastOutput output,
        ulong maximumOutboundPayloadLength,
        out BsvPeerSessionOutputDisposition disposition)
    {
        disposition = BsvPeerSessionOutputDisposition.Send;
        if (!EnsureIdle())
        {
            return Fault();
        }

        if (output.Kind == BsvTransactionBroadcastOutputKind.SendInventory)
        {
            return StartInventory(
                BsvPeerSessionSendKind.Inventory,
                BsvPeerSessionRelayWriteCommitKind.Inventory,
                "inv"u8,
                output.TransactionId,
                maximumOutboundPayloadLength);
        }

        if (output.Kind is BsvTransactionBroadcastOutputKind.Announced or
            BsvTransactionBroadcastOutputKind.RequestedByPeer or
            BsvTransactionBroadcastOutputKind.SentToPeer or
            BsvTransactionBroadcastOutputKind.ObservedFromPeer or
            BsvTransactionBroadcastOutputKind.Rejected)
        {
            disposition = BsvPeerSessionOutputDisposition.Fact;
            return OperationStatus.Done;
        }

        return Fault();
    }

    internal OperationStatus PlanTransaction(
        in BsvTransactionBroadcastOutput output,
        ulong payloadLength,
        Hash256 expectedTransactionId,
        ulong maximumOutboundPayloadLength)
    {
        if (!EnsureIdle() ||
            output.Kind != BsvTransactionBroadcastOutputKind.SendTransaction ||
            output.TransactionId != expectedTransactionId ||
            payloadLength == 0)
        {
            return Fault();
        }

        Span<byte> transactionIdBytes = stackalloc byte[Hash256.Length];
        _ = expectedTransactionId.TryCopyWireBytesTo(transactionIdBytes, out _);
        MessageHeader header;
        var headerStatus = payloadLength <= uint.MaxValue
            ? MessageHeader.TryCreateBasic(
                "tx"u8,
                (uint)payloadLength,
                transactionIdBytes[..MessageChecksum.Length],
                out header)
            : MessageHeader.TryCreateExtended("tx"u8, payloadLength, out header);
        if (headerStatus != OperationStatus.Done)
        {
            return Fault();
        }

        _transactionHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        _sendKind = BsvPeerSessionSendKind.Transaction;
        _relayWriteCommitKind = BsvPeerSessionRelayWriteCommitKind.Transaction;
        _transactionId = expectedTransactionId;
        _fixedPayloadLength = 0;
        if (!TryReservePlanId())
        {
            return Fault();
        }

        _state = BsvPeerSessionEgressState.Active;
        if (_writer.Start(_networkMagic, header, maximumOutboundPayloadLength) != OperationStatus.Done)
        {
            return Fault();
        }

        return OperationStatus.Done;
    }

    internal OperationStatus PlanFetch(
        in BsvTransactionFetchOutput output,
        ulong maximumOutboundPayloadLength,
        out BsvPeerSessionOutputDisposition disposition)
    {
        disposition = BsvPeerSessionOutputDisposition.Send;
        if (!EnsureIdle())
        {
            return Fault();
        }

        if (output.Kind == BsvTransactionFetchOutputKind.SendGetData)
        {
            return StartInventory(
                BsvPeerSessionSendKind.GetData,
                BsvPeerSessionRelayWriteCommitKind.GetData,
                "getdata"u8,
                output.TransactionId,
                maximumOutboundPayloadLength);
        }

        if (output.Kind is BsvTransactionFetchOutputKind.Requested or
            BsvTransactionFetchOutputKind.UnexpectedTransaction or
            BsvTransactionFetchOutputKind.Received or
            BsvTransactionFetchOutputKind.NotFound)
        {
            disposition = BsvPeerSessionOutputDisposition.Fact;
            return OperationStatus.Done;
        }

        return Fault();
    }

    internal OperationStatus ProvideTransactionChunk(ReadOnlyMemory<byte> chunk)
    {
        if (_state != BsvPeerSessionEgressState.Active ||
            _sendKind != BsvPeerSessionSendKind.Transaction ||
            _writer.ProvidePayloadChunk(chunk) != OperationStatus.Done)
        {
            return Fault();
        }

        return OperationStatus.Done;
    }

    internal OperationStatus Acknowledge(
        in MessageFrameWriteSegment segment,
        int bytesWritten)
    {
        if (_state != BsvPeerSessionEgressState.Active)
        {
            return Fault();
        }

        var hashTransactionBytes =
            _sendKind == BsvPeerSessionSendKind.Transaction &&
            _writer.Phase == MessageFrameWritePhase.Payload &&
            bytesWritten > 0 &&
            bytesWritten <= segment.Length;
        var acknowledgedTransactionBytes = hashTransactionBytes
            ? segment.Memory[..bytesWritten]
            : ReadOnlyMemory<byte>.Empty;

        if (_writer.Acknowledge(segment, bytesWritten) != OperationStatus.Done)
        {
            return Fault();
        }

        if (hashTransactionBytes)
        {
            _transactionHash!.AppendData(acknowledgedTransactionBytes.Span);
        }

        if (_writer.Phase == MessageFrameWritePhase.AwaitingPayload &&
            _sendKind != BsvPeerSessionSendKind.Transaction)
        {
            if (_writer.ProvidePayloadChunk(
                    _fixedPayload.AsMemory(0, _fixedPayloadLength)) != OperationStatus.Done)
            {
                return Fault();
            }
        }

        if (_writer.IsComplete)
        {
            return Complete();
        }

        return OperationStatus.Done;
    }

    /// <summary>Signals caller EOF for the active transaction; incomplete input faults permanently.</summary>
    internal OperationStatus EndTransactionPayload()
    {
        if (_state == BsvPeerSessionEgressState.Complete &&
            _sendKind == BsvPeerSessionSendKind.Transaction)
        {
            return OperationStatus.Done;
        }

        return Fault();
    }

    internal OperationStatus Reset()
    {
        ObjectDisposedException.ThrowIf(_state == BsvPeerSessionEgressState.Disposed, this);
        if (_state != BsvPeerSessionEgressState.Complete ||
            !_completionConsumed ||
            _writer.Reset() != OperationStatus.Done)
        {
            return Fault();
        }

        ClearSend();
        _state = BsvPeerSessionEgressState.Idle;
        return OperationStatus.Done;
    }

    internal OperationStatus Abort()
    {
        ObjectDisposedException.ThrowIf(_state == BsvPeerSessionEgressState.Disposed, this);
        if (_state != BsvPeerSessionEgressState.Active ||
            _writer.Abort() != OperationStatus.Done)
        {
            return Fault();
        }

        ClearSend();
        _state = BsvPeerSessionEgressState.Aborted;
        return OperationStatus.Done;
    }

    public void Dispose()
    {
        if (_state == BsvPeerSessionEgressState.Disposed)
        {
            return;
        }

        ClearSend();
        _writer.Dispose();
        _state = BsvPeerSessionEgressState.Disposed;
    }

    private OperationStatus StartInventory(
        BsvPeerSessionSendKind sendKind,
        BsvPeerSessionRelayWriteCommitKind commitKind,
        ReadOnlySpan<byte> command,
        Hash256 transactionId,
        ulong maximumOutboundPayloadLength)
    {
        Span<InventoryVector> vector = stackalloc InventoryVector[1];
        vector[0] = new InventoryVector(type: 1, transactionId);
        if (InventoryPayloadCodec.TryWrite(
                vector,
                _fixedPayload,
                MaximumFixedPayloadLength,
                out _fixedPayloadLength) != OperationStatus.Done)
        {
            return Fault();
        }

        _relayWriteCommitKind = commitKind;
        _transactionId = transactionId;
        return StartFixed(
            sendKind,
            command,
            _fixedPayloadLength,
            value: 0,
            maximumOutboundPayloadLength);
    }

    private OperationStatus StartFixed(
        BsvPeerSessionSendKind sendKind,
        ReadOnlySpan<byte> command,
        int payloadLength,
        ulong value,
        ulong maximumOutboundPayloadLength)
    {
        var checksum = MessageChecksum.Compute(_fixedPayload.AsSpan(0, payloadLength));
        Span<byte> checksumBytes = stackalloc byte[MessageChecksum.Length];
        _ = checksum.TryCopyTo(checksumBytes, out _);
        if (MessageHeader.TryCreateBasic(
                command,
                (uint)payloadLength,
                checksumBytes,
                out var header) != OperationStatus.Done)
        {
            return Fault();
        }

        _sendKind = sendKind;
        _value = value;
        _fixedPayloadLength = payloadLength;
        if (!TryReservePlanId())
        {
            return Fault();
        }

        _state = BsvPeerSessionEgressState.Active;
        if (_writer.Start(_networkMagic, header, maximumOutboundPayloadLength) != OperationStatus.Done)
        {
            return Fault();
        }

        return OperationStatus.Done;
    }

    private OperationStatus Complete()
    {
        if (_sendKind == BsvPeerSessionSendKind.Transaction)
        {
            Span<byte> firstHash = stackalloc byte[Hash256.Length];
            Span<byte> secondHash = stackalloc byte[Hash256.Length];
            if (!_transactionHash!.TryGetHashAndReset(firstHash, out var firstHashLength) ||
                firstHashLength != Hash256.Length)
            {
                return Fault();
            }

            SHA256.HashData(firstHash, secondHash);
            if (Hash256.TryCreate(secondHash, out var actualTransactionId) != OperationStatus.Done ||
                actualTransactionId != _transactionId)
            {
                return Fault();
            }
        }

        _transactionHash?.Dispose();
        _transactionHash = null;
        _completion = new BsvPeerSessionEgressCompletion(
            _planId,
            _sendKind,
            _relayWriteCommitKind,
            _transactionId,
            _value);
        _completionConsumed = false;
        _state = BsvPeerSessionEgressState.Complete;
        return OperationStatus.Done;
    }

    private bool EnsureIdle()
    {
        ObjectDisposedException.ThrowIf(_state == BsvPeerSessionEgressState.Disposed, this);
        return _state == BsvPeerSessionEgressState.Idle;
    }

    private bool TryReservePlanId()
    {
        if (_nextPlanId == 0)
        {
            return false;
        }

        _planId = _nextPlanId;
        _nextPlanId++;
        return true;
    }

    private OperationStatus Fault()
    {
        ObjectDisposedException.ThrowIf(_state == BsvPeerSessionEgressState.Disposed, this);
        if (_writer.Phase is MessageFrameWritePhase.Header or
            MessageFrameWritePhase.AwaitingPayload or
            MessageFrameWritePhase.Payload)
        {
            _ = _writer.Abort();
        }
        else if (_writer.Phase is MessageFrameWritePhase.Complete or MessageFrameWritePhase.Aborted)
        {
            _ = _writer.Reset();
        }

        ClearSend();
        _state = BsvPeerSessionEgressState.Faulted;
        return OperationStatus.InvalidData;
    }

    private void ClearSend()
    {
        _transactionHash?.Dispose();
        _transactionHash = null;
        _fixedPayload.AsSpan().Clear();
        _fixedPayloadLength = 0;
        _sendKind = BsvPeerSessionSendKind.None;
        _relayWriteCommitKind = BsvPeerSessionRelayWriteCommitKind.None;
        _transactionId = default;
        _value = 0;
        _planId = 0;
        _completion = default;
        _completionConsumed = false;
    }
}
