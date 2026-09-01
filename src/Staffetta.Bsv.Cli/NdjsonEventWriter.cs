using System.Text.Json;
using System.Text.Json.Serialization;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
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
    private long _sequence;

    internal NdjsonEventWriter(TextWriter writer) =>
        _writer = writer ?? throw new ArgumentNullException(nameof(writer));

    internal ValueTask WriteConnectionOpenedAsync(
        string requestedPeer,
        string remotePeer,
        CancellationToken cancellationToken = default) =>
        WriteAsync(
            new ConnectionOpenedEvent(
                Schema,
                NextSequence(),
                "connection.opened",
                requestedPeer,
                remotePeer),
            cancellationToken);

    internal ValueTask WriteHandshakeReadyAsync(
        string peer,
        in BsvPeerReadySnapshot snapshot,
        CancellationToken cancellationToken = default) =>
        WriteAsync(
            new HandshakeReadyEvent(
                Schema,
                NextSequence(),
                "handshake.ready",
                peer,
                snapshot.ProtocolVersion,
                snapshot.EffectiveMaximumReceivePayloadLength.ToString(System.Globalization.CultureInfo.InvariantCulture),
                snapshot.HasProtoconf),
            cancellationToken);

    internal ValueTask WriteHandshakeRejectedAsync(
        string peer,
        CancellationToken cancellationToken = default) =>
        WriteAsync(new HandshakeRejectedEvent(Schema, NextSequence(), "handshake.rejected", peer), cancellationToken);

    internal ValueTask WriteBroadcastPreparedAsync(
        in LegacyTransactionSummary summary,
        CancellationToken cancellationToken = default) =>
        WriteAsync(
            new BroadcastPreparedEvent(
                Schema,
                NextSequence(),
                "broadcast.prepared",
                summary.TransactionId.ToDisplayHex(),
                Format(summary.SerializedLength),
                Format(summary.InputCount),
                Format(summary.OutputCount),
                false),
            cancellationToken);

    internal ValueTask WriteSessionTerminalAsync(
        string stage,
        string kind,
        string reason,
        BsvHandshakeTerminalReason? handshakeReason = null,
        CancellationToken cancellationToken = default) =>
        WriteAsync(
            new SessionTerminalEvent(
                Schema,
                NextSequence(),
                "session.terminal",
                stage,
                kind,
                reason,
                handshakeReason?.ToString()),
            cancellationToken);

    internal ValueTask WriteSessionStoppedAsync(
        CancellationToken cancellationToken = default) =>
        WriteAsync(
            new SessionStoppedEvent(Schema, NextSequence(), "session.stopped", "completed"),
            cancellationToken);

    private static string Format(ulong value) =>
        value.ToString(System.Globalization.CultureInfo.InvariantCulture);

    private long NextSequence() => checked(++_sequence);

    private async ValueTask WriteAsync<T>(T value, CancellationToken cancellationToken)
    {
        var line = JsonSerializer.Serialize(value, SerializerOptions);
        await _writer.WriteLineAsync(line.AsMemory(), cancellationToken).ConfigureAwait(false);
        await _writer.FlushAsync(cancellationToken).ConfigureAwait(false);
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
