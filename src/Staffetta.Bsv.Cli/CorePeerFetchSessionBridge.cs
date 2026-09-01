using System.Net;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Relay;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Transport;

namespace Staffetta.Bsv.Cli;

internal sealed class CorePeerFetchSessionBridge : IBsvPeerSessionFactSink, IAsyncDisposable
{
    private static readonly byte[] MainnetMagic = [0xe3, 0xe1, 0xf3, 0xe8];

    private const ulong Services = 0;
    private const ulong MaximumInboundPayloadLength = 16 * 1024 * 1024;

    private readonly string _peer;
    private readonly Hash256 _targetTransactionId;
    private readonly NdjsonEventWriter _events;
    private readonly BsvPeerStreamTransportActor _actor;
    private readonly TaskCompletionSource _ready =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _applicationReported =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _received =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _receivedBeforeRequest =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _requested =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _notFound =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<BsvTransactionMonetaryValidation> _monetaryInvalid =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal CorePeerFetchSessionBridge(
        Stream stream,
        IPAddress remoteAddress,
        int remotePort,
        string peer,
        Hash256 targetTransactionId,
        NdjsonEventWriter events,
        long timestampUnixSeconds,
        ulong nonce)
    {
        _peer = peer;
        _targetTransactionId = targetTransactionId;
        _events = events;
        var receivingAddress = new NetworkAddress(
            Services,
            remoteAddress.MapToIPv6().GetAddressBytes(),
            checked((ushort)remotePort));
        var sourceAddress = new NetworkAddress(Services, new byte[16], 0);
        var localHandshake = new BsvPeerLocalHandshakeConfiguration(
            VersionPayloadCodec.CurrentProtocolVersion,
            Services,
            timestampUnixSeconds,
            receivingAddress,
            sourceAddress,
            nonce,
            "/Staffetta:reference-cli/"u8,
            startHeight: 0,
            relay: true,
            maximumReceivePayloadLength: (uint)MaximumInboundPayloadLength,
            "Default"u8,
            includeStreamPolicies: true);
        _actor = new BsvPeerStreamTransportActor(
            stream,
            MainnetMagic,
            MaximumInboundPayloadLength,
            VersionPayloadCodec.CurrentProtocolVersion,
            localHandshake,
            NoOpTransactionSink.Instance,
            RejectingTransactionSourceProvider.Instance,
            this,
            new BsvPeerStreamTransportOptions(leaveOpen: true));
    }

    internal Task Ready => _ready.Task;

    internal string Peer => _peer;

    internal Hash256 TargetTransactionId => _targetTransactionId;

    internal Task Received => _received.Task;

    internal Task ReceivedBeforeRequest => _receivedBeforeRequest.Task;

    internal Task NotFound => _notFound.Task;

    internal Task<BsvTransactionMonetaryValidation> MonetaryInvalid => _monetaryInvalid.Task;

    internal BsvHandshakeTerminalReason HandshakeTerminalReason =>
        _actor.HandshakeTerminalReason;

    internal BsvPeerTransportCommandSubmission QueueFetch() =>
        _actor.QueueFetch(_targetTransactionId);

    internal Task<BsvPeerTransportActorCompletion> RunAsync() => _actor.RunAsync();

    internal ValueTask StopAsync() => _actor.StopAsync();

    internal async Task<BsvPeerTransportCommandApplication> ReportApplicationAsync(
        Task<BsvPeerTransportCommandApplication> application)
    {
        try
        {
            var applied = await application.ConfigureAwait(false);
            await _events.WriteFetchApplicationAsync(
                    _peer,
                    _targetTransactionId,
                    applied,
                    CancellationToken.None)
                .ConfigureAwait(false);
            _applicationReported.TrySetResult();
            return applied;
        }
        catch (Exception exception)
        {
            _applicationReported.TrySetException(exception);
            throw;
        }
    }

    public ValueTask DisposeAsync() => _actor.DisposeAsync();

    public async ValueTask OnHandshakeFactAsync(
        BsvHandshakeOutput output,
        CancellationToken cancellationToken)
    {
        if (output.Kind == BsvHandshakeOutputKind.BecameReady)
        {
            if (!_actor.TryGetReadyPeerSnapshot(out var snapshot))
            {
                throw new InvalidOperationException("The Ready fact did not have a peer snapshot.");
            }

            await _events.WriteHandshakeReadyAsync(_peer, snapshot, cancellationToken)
                .ConfigureAwait(false);
            _ready.TrySetResult();
        }
        else if (output.Kind == BsvHandshakeOutputKind.ForwardReject)
        {
            await _events.WriteHandshakeRejectedAsync(_peer, cancellationToken).ConfigureAwait(false);
        }
    }

    public ValueTask OnBroadcastFactAsync(
        BsvTransactionBroadcastOutput output,
        CancellationToken cancellationToken) =>
        ValueTask.FromException(new InvalidOperationException("The reference fetch command cannot broadcast."));

    public async ValueTask OnFetchFactAsync(
        BsvTransactionFetchOutput output,
        CancellationToken cancellationToken)
    {
        await _applicationReported.Task.ConfigureAwait(false);
        await _events.WriteFetchFactAsync(_peer, output, cancellationToken).ConfigureAwait(false);
        if (output.TransactionId != _targetTransactionId)
        {
            return;
        }

        if (output.Kind == BsvTransactionFetchOutputKind.Requested)
        {
            _requested.TrySetResult();
        }
        else if (output.Kind == BsvTransactionFetchOutputKind.Received)
        {
            if (_requested.Task.IsCompletedSuccessfully)
            {
                _received.TrySetResult();
            }
            else
            {
                _receivedBeforeRequest.TrySetResult();
            }
        }
        else if (output.Kind == BsvTransactionFetchOutputKind.NotFound)
        {
            _notFound.TrySetResult();
        }
    }

    public async ValueTask OnMonetaryValidationFactAsync(
        BsvTransactionMonetaryValidation validation,
        CancellationToken cancellationToken)
    {
        await _events.WriteMonetaryValidationAsync(validation, cancellationToken).ConfigureAwait(false);
        if (validation.TransactionId == _targetTransactionId && _requested.Task.IsCompletedSuccessfully)
        {
            _monetaryInvalid.TrySetResult(validation);
        }
    }

    private sealed class RejectingTransactionSourceProvider : IBsvTransactionPayloadSourceProvider
    {
        internal static RejectingTransactionSourceProvider Instance { get; } = new();

        public ValueTask<IBsvTransactionPayloadSource?> OpenAsync(
            Hash256 transactionId,
            CancellationToken cancellationToken) =>
            ValueTask.FromException<IBsvTransactionPayloadSource?>(
                new InvalidOperationException("The reference fetch command cannot open transaction bytes."));
    }

    private sealed class NoOpTransactionSink : ILegacyTransactionSink
    {
        internal static NoOpTransactionSink Instance { get; } = new();

        public void OnTransactionStarted(int version, ulong inputCount) { }

        public void OnInputStarted(ulong inputIndex, in OutPoint previousOutput, ulong scriptLength) { }

        public void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script) { }

        public void OnInputCompleted(ulong inputIndex, uint sequence) { }

        public void OnOutputsStarted(ulong outputCount) { }

        public void OnOutputStarted(ulong outputIndex, long valueSatoshis, ulong scriptLength) { }

        public void OnOutputScriptChunk(ulong outputIndex, ReadOnlySpan<byte> script) { }

        public void OnOutputCompleted(ulong outputIndex) { }

        public void OnTransactionCommitted(in LegacyTransactionSummary summary) { }

        public void OnTransactionAborted() { }
    }
}
