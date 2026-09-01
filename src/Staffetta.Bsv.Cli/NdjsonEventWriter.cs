using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Channels;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Relay;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Transport;

namespace Staffetta.Bsv.Cli;

internal sealed class NdjsonEventWriter
{
    internal const string Schema = "staffetta.bsv.reference-cli.event.v1";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly TextWriter _writer;
    private readonly Channel<bool> _writeGate = CreateWriteGate();
    private long _sequence;

    internal NdjsonEventWriter(TextWriter writer) =>
        _writer = writer ?? throw new ArgumentNullException(nameof(writer));

    internal ValueTask WriteConnectionOpenedAsync(
        string requestedPeer,
        string remotePeer,
        CancellationToken cancellationToken = default) =>
        WriteAsync(
            sequence => new ConnectionOpenedEvent(
                Schema,
                sequence,
                "connection.opened",
                requestedPeer,
                remotePeer),
            cancellationToken);

    internal ValueTask WriteHandshakeReadyAsync(
        string peer,
        BsvPeerReadySnapshot snapshot,
        CancellationToken cancellationToken = default) =>
        WriteAsync(
            sequence => new HandshakeReadyEvent(
                Schema,
                sequence,
                "handshake.ready",
                peer,
                snapshot.ProtocolVersion,
                snapshot.EffectiveMaximumReceivePayloadLength.ToString(System.Globalization.CultureInfo.InvariantCulture),
                snapshot.HasProtoconf),
            cancellationToken);

    internal ValueTask WriteHandshakeRejectedAsync(
        string peer,
        CancellationToken cancellationToken = default) =>
        WriteAsync(sequence => new HandshakeRejectedEvent(Schema, sequence, "handshake.rejected", peer), cancellationToken);

    internal ValueTask WriteBroadcastPreparedAsync(
        LegacyTransactionSummary summary,
        bool willBroadcast = false,
        CancellationToken cancellationToken = default) =>
        WriteAsync(
            sequence => new BroadcastPreparedEvent(
                Schema,
                sequence,
                "broadcast.prepared",
                summary.TransactionId.ToDisplayHex(),
                Format(summary.SerializedLength),
                Format(summary.InputCount),
                Format(summary.OutputCount),
                willBroadcast),
            cancellationToken);

    internal ValueTask WriteBroadcastQueueAsync(
        Hash256 transactionId,
        BsvPeerTransportCommandQueueStatus status,
        CancellationToken cancellationToken = default) =>
        WriteAsync(
            sequence => new BroadcastQueueEvent(
                Schema,
                sequence,
                "broadcast.queue",
                transactionId.ToDisplayHex(),
                status.ToString()),
            cancellationToken);

    internal ValueTask WriteBroadcastApplicationAsync(
        Hash256 transactionId,
        BsvPeerTransportCommandApplication application,
        CancellationToken cancellationToken = default) =>
        WriteAsync(
            sequence => new BroadcastApplicationEvent(
                Schema,
                sequence,
                "broadcast.application",
                transactionId.ToDisplayHex(),
                application.Kind.ToString(),
                application.Status.ToString()),
            cancellationToken);

    internal ValueTask WriteBroadcastFactAsync(
        BsvTransactionBroadcastOutput output,
        CancellationToken cancellationToken = default) =>
        WriteAsync(
            sequence => new BroadcastFactEvent(
                Schema,
                sequence,
                "broadcast.fact",
                output.TransactionId.ToDisplayHex(),
                output.Kind.ToString()),
            cancellationToken);

    internal ValueTask WriteBroadcastObservationAsync(
        Hash256 transactionId,
        string outcome,
        string reason,
        string? transportKind = null,
        string? transportReason = null,
        CancellationToken cancellationToken = default) =>
        WriteAsync(
            sequence => new BroadcastObservationEvent(
                Schema,
                sequence,
                "broadcast.observation",
                transactionId.ToDisplayHex(),
                outcome,
                reason,
                transportKind,
                transportReason),
            cancellationToken);

    internal ValueTask WriteSessionTerminalAsync(
        string stage,
        string kind,
        string reason,
        BsvHandshakeTerminalReason? handshakeReason = null,
        CancellationToken cancellationToken = default) =>
        WriteAsync(
            sequence => new SessionTerminalEvent(
                Schema,
                sequence,
                "session.terminal",
                stage,
                kind,
                reason,
                handshakeReason?.ToString()),
            cancellationToken);

    internal ValueTask WriteSessionStoppedAsync(
        string reason = "completed",
        CancellationToken cancellationToken = default) =>
        WriteAsync(
            sequence => new SessionStoppedEvent(Schema, sequence, "session.stopped", reason),
            cancellationToken);

    private static string Format(ulong value) =>
        value.ToString(System.Globalization.CultureInfo.InvariantCulture);

    private async ValueTask WriteAsync<T>(Func<long, T> create, CancellationToken cancellationToken)
    {
        _ = await _writeGate.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var value = create(checked(++_sequence));
            var line = JsonSerializer.Serialize(value, SerializerOptions);
            await _writer.WriteLineAsync(line.AsMemory(), cancellationToken).ConfigureAwait(false);
            await _writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = _writeGate.Writer.TryWrite(true);
        }
    }

    private static Channel<bool> CreateWriteGate()
    {
        var gate = Channel.CreateBounded<bool>(new BoundedChannelOptions(1)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = false,
            SingleWriter = false,
            AllowSynchronousContinuations = false,
        });
        if (!gate.Writer.TryWrite(true))
        {
            throw new InvalidOperationException("The NDJSON write gate could not be initialized.");
        }

        return gate;
    }

    private sealed record ConnectionOpenedEvent(
        string Schema,
        long Sequence,
        string Type,
        string RequestedPeer,
        string RemotePeer);

    private sealed record HandshakeReadyEvent(
        string Schema,
        long Sequence,
        string Type,
        string Peer,
        int ProtocolVersion,
        string EffectivePeerMaximumReceivePayloadLength,
        bool PeerProtoconfObserved);

    private sealed record HandshakeRejectedEvent(
        string Schema,
        long Sequence,
        string Type,
        string Peer);

    private sealed record BroadcastPreparedEvent(
        string Schema,
        long Sequence,
        string Type,
        string Txid,
        string TransactionLength,
        string InputCount,
        string OutputCount,
        bool WillBroadcast);

    private sealed record BroadcastQueueEvent(
        string Schema,
        long Sequence,
        string Type,
        string Txid,
        string Status);

    private sealed record BroadcastApplicationEvent(
        string Schema,
        long Sequence,
        string Type,
        string Txid,
        string Kind,
        string Status);

    private sealed record BroadcastFactEvent(
        string Schema,
        long Sequence,
        string Type,
        string Txid,
        string Fact);

    private sealed record BroadcastObservationEvent(
        string Schema,
        long Sequence,
        string Type,
        string Txid,
        string Outcome,
        string Reason,
        string? TransportKind,
        string? TransportReason);

    private sealed record SessionTerminalEvent(
        string Schema,
        long Sequence,
        string Type,
        string Stage,
        string Kind,
        string Reason,
        string? HandshakeReason);

    private sealed record SessionStoppedEvent(
        string Schema,
        long Sequence,
        string Type,
        string Reason);
}
