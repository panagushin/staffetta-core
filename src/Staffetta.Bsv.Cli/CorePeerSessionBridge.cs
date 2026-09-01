using System.Net;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Relay;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Transport;

namespace Staffetta.Bsv.Cli;

internal sealed class CorePeerSessionBridge : IBsvPeerSessionFactSink, IAsyncDisposable
{
    private static readonly byte[] MainnetMagic = [0xe3, 0xe1, 0xf3, 0xe8];

    private const ulong Services = 0;
    private const ulong MaximumInboundPayloadLength = 16 * 1024 * 1024;

    private readonly string _peer;
    private readonly NdjsonEventWriter _events;
    private readonly BsvPeerStreamTransportActor _actor;
    private readonly bool _allowBroadcast;
    private readonly TaskCompletionSource _ready =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<BsvTransactionBroadcastOutputKind> _deliveryOutcome =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _observedFromPeer =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _rejected =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _applicationReported =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal CorePeerSessionBridge(
        Stream stream,
        IPAddress remoteAddress,
        int remotePort,
        string peer,
        NdjsonEventWriter events,
        long timestampUnixSeconds,
        ulong nonce)
        : this(
            stream,
            remoteAddress,
            remotePort,
            peer,
            events,
            timestampUnixSeconds,
            nonce,
            RejectingTransactionSourceProvider.Instance,
            allowBroadcast: false)
    {
    }

    internal CorePeerSessionBridge(
        Stream stream,
        IPAddress remoteAddress,
        int remotePort,
        string peer,
        NdjsonEventWriter events,
        long timestampUnixSeconds,
        ulong nonce,
        IBsvTransactionPayloadSourceProvider transactionSources)
        : this(
            stream,
            remoteAddress,
            remotePort,
            peer,
            events,
            timestampUnixSeconds,
            nonce,
            transactionSources,
            allowBroadcast: true)
    {
    }

    private CorePeerSessionBridge(
        Stream stream,
        IPAddress remoteAddress,
        int remotePort,
        string peer,
        NdjsonEventWriter events,
        long timestampUnixSeconds,
        ulong nonce,
        IBsvTransactionPayloadSourceProvider transactionSources,
        bool allowBroadcast)
    {
        _peer = peer;
        _events = events;
        _allowBroadcast = allowBroadcast;
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
            relay: false,
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
            transactionSources,
            this,
            new BsvPeerStreamTransportOptions(leaveOpen: true));
    }

    internal Task Ready => _ready.Task;

    internal Task<BsvTransactionBroadcastOutputKind> DeliveryOutcome => _deliveryOutcome.Task;

    internal Task ObservedFromPeer => _observedFromPeer.Task;

    internal Task Rejected => _rejected.Task;

    internal BsvHandshakeTerminalReason HandshakeTerminalReason =>
        _actor.HandshakeTerminalReason;

    internal Task<BsvPeerTransportActorCompletion> RunAsync() => _actor.RunAsync();

    internal ValueTask StopAsync() => _actor.StopAsync();

    internal BsvPeerTransportCommandSubmission QueueBroadcast(Hash256 transactionId)
    {
        if (!_allowBroadcast)
        {
            throw new InvalidOperationException("The reference handshake command cannot broadcast.");
        }

        return _actor.QueueBroadcast(transactionId);
    }

    internal async Task<BsvPeerTransportCommandApplication> ReportBroadcastApplicationAsync(
        Hash256 transactionId,
        Task<BsvPeerTransportCommandApplication> application)
    {
        try
        {
            var applied = await application.ConfigureAwait(false);
            await _events.WriteBroadcastApplicationAsync(transactionId, applied, CancellationToken.None)
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

    public async ValueTask OnBroadcastFactAsync(
        BsvTransactionBroadcastOutput output,
        CancellationToken cancellationToken)
    {
        if (!_allowBroadcast)
        {
            throw new InvalidOperationException("The reference handshake command cannot broadcast.");
        }

        await _applicationReported.Task.ConfigureAwait(false);
        await _events.WriteBroadcastFactAsync(output, cancellationToken).ConfigureAwait(false);
        if (output.Kind == BsvTransactionBroadcastOutputKind.SentToPeer)
        {
            _deliveryOutcome.TrySetResult(output.Kind);
        }
        else if (output.Kind == BsvTransactionBroadcastOutputKind.ObservedFromPeer)
        {
            _observedFromPeer.TrySetResult();
        }
        else if (output.Kind == BsvTransactionBroadcastOutputKind.Rejected)
        {
            _rejected.TrySetResult();
            _deliveryOutcome.TrySetResult(output.Kind);
        }
    }

    public ValueTask OnFetchFactAsync(
        BsvTransactionFetchOutput output,
        CancellationToken cancellationToken) =>
        ValueTask.FromException(new InvalidOperationException("The reference handshake command cannot fetch."));

    public ValueTask OnMonetaryValidationFactAsync(
        BsvTransactionMonetaryValidation validation,
        CancellationToken cancellationToken) =>
        _events.WriteMonetaryValidationAsync(validation, cancellationToken);

    private sealed class RejectingTransactionSourceProvider : IBsvTransactionPayloadSourceProvider
    {
        internal static RejectingTransactionSourceProvider Instance { get; } = new();

        public ValueTask<IBsvTransactionPayloadSource?> OpenAsync(
            Hash256 transactionId,
            CancellationToken cancellationToken) =>
            ValueTask.FromException<IBsvTransactionPayloadSource?>(
                new InvalidOperationException("The reference handshake command cannot open transaction bytes."));
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
