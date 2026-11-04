using System.Buffers;
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Messages;
using Staffetta.Core.Protocol.Sessions;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Bsv.LiveProbe;

// Isolated, bounded BIP-35 experiment. No broadcast, peer pool, database or production retry policy.
internal static class MempoolProbe
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    internal const int MaximumSampleTransactions = 8;
    internal const int MaximumInventory = 50_000;
    internal const int MaximumPayload = 16 * 1024 * 1024;
    internal const long MaximumReceivedBytes = 64 * 1024 * 1024;

    internal static async Task<int> RunAsync(MempoolProbeOptions options)
    {
        if (Directory.Exists(options.OutputDirectory))
        {
            throw new ArgumentException("Probe output directory must be new.");
        }

        Directory.CreateDirectory(options.OutputDirectory);
        var evidence = new MempoolEvidence(options.Peer.ToString(), options.Relay, options.Seconds)
        {
            RequestMempool = options.RequestMempool,
        };
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(options.Seconds));
        using var client = new TcpClient(AddressFamily.InterNetwork);
        var result = 0;
        try
        {
            var snapshot = await RepositorySnapshot.ReadAsync(deadline.Token).ConfigureAwait(false);
            evidence.RepositoryCommit = snapshot.Commit;
            evidence.RepositoryState = snapshot.State;
            using (var connect = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token))
            {
                connect.CancelAfter(TimeSpan.FromSeconds(5));
                await client.ConnectAsync(options.Peer, connect.Token).ConfigureAwait(false);
            }

            await using var stream = client.GetStream();
            await RunConnectedAsync(options, stream, evidence, deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            evidence.EndReason = deadline.IsCancellationRequested ? "bounded_deadline" : "connect_timeout";
            result = evidence.HandshakeReady ? 0 : 1;
        }
        catch (Exception exception) when (exception is IOException or SocketException or InvalidOperationException)
        {
            evidence.EndReason = exception is EndOfStreamException ? "peer_closed_or_truncated" : exception.GetType().Name;
            evidence.Failure = exception.Message;
            result = 1;
        }

        evidence.FinishedAt = DateTimeOffset.UtcNow;
        var json = JsonSerializer.Serialize(evidence, JsonOptions);
        await File.WriteAllTextAsync(Path.Combine(options.OutputDirectory, "evidence.json"), json).ConfigureAwait(false);
        Console.WriteLine(json);
        return result;
    }

    internal static async Task RunConnectedAsync(MempoolProbeOptions options, Stream stream,
        MempoolEvidence evidence, CancellationToken cancellationToken)
    {
        var sink = new SampleSink(evidence);
        using var session = new BsvPeerObservationSession(ProbeWireEncoder.NetworkMagic, MaximumPayload,
            ProbeWireEncoder.MinimumAcceptedPeerProtocolVersion, sink);
        var version = new VersionPayload(VersionPayloadCodec.CurrentProtocolVersion, 0,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds(), default, default,
            BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8)), "/Staffetta:mempool-probe/"u8, 0, options.Relay);
        RequireDone(session.StartHandshake(version, MaximumPayload));
        var buffer = new byte[4096];
        var headerBytes = new byte[MessageHeaderCodec.BasicHeaderLength];
        var inventory = new InventoryVector[MaximumInventory];
        var headers = new BlockHeader[2000];
        var verdicts = new BsvTransactionMonetaryValidation[1];
        var seen = new HashSet<Hash256>();
        var requested = new HashSet<Hash256>();
        var started = Stopwatch.StartNew();

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            while (session.TryGetWrite(out var write))
            {
                await stream.WriteAsync(write.Bytes, cancellationToken).ConfigureAwait(false);
                RequireDone(session.AcknowledgeWrite(write, write.Bytes.Length));
            }

            if (session.HandshakeState == BsvHandshakeState.Terminal)
            {
                throw new InvalidDataException("Peer handshake terminated.");
            }

            evidence.HandshakeReady = session.HandshakeState == BsvHandshakeState.Ready;
            if (evidence.Frames >= 1024)
            {
                throw new InvalidDataException("Probe frame count budget exceeded.");
            }

            if (evidence.HandshakeReady && options.RequestMempool && evidence.MempoolRequests == 0)
            {
                // The production session has no mempool intent yet. Only this exploratory harness
                // writes the empty BIP-35 command directly after all handshake writes complete.
                await stream.WriteAsync(ProbeWireEncoder.EncodeFrame("mempool"u8, []), cancellationToken).ConfigureAwait(false);
                evidence.MempoolRequests++;
                evidence.RequestAtMilliseconds = started.ElapsedMilliseconds;
            }

            await stream.ReadExactlyAsync(headerBytes, cancellationToken).ConfigureAwait(false);
            RequireDone(MessageHeaderCodec.TryParse(headerBytes, ProbeWireEncoder.NetworkMagic, MaximumPayload,
                out var header, out var headerLength));
            if (header.Format != MessageHeaderFormat.Basic || headerLength != headerBytes.Length ||
                evidence.ReceivedBytes + headerBytes.Length + (long)header.PayloadLength > MaximumReceivedBytes)
            {
                throw new InvalidDataException("Probe frame format or byte budget exceeded.");
            }

            var commandBytes = new byte[MessageCommand.MaximumLength];
            RequireDone(header.Command.TryCopyTo(commandBytes, out var commandLength));
            var command = Encoding.ASCII.GetString(commandBytes, 0, commandLength);
            var candidate = Path.Combine(options.OutputDirectory, $"frame-{evidence.Frames:D6}.partial");
            await using (var capture = new FileStream(candidate, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.Asynchronous))
            {
                await capture.WriteAsync(headerBytes, cancellationToken).ConfigureAwait(false);
                Consume(session, headerBytes);
                var remaining = header.PayloadLength;
                // Version/reject are bounded control metadata; transaction bytes stay streamed.
                var retained = command is "version" or "reject" && remaining <= 4096 ? new MemoryStream() : null;
                using (retained)
                {
                    while (remaining != 0)
                    {
                        var count = (int)Math.Min((ulong)buffer.Length, remaining);
                        await stream.ReadExactlyAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
                        await capture.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
                        retained?.Write(buffer, 0, count);
                        Consume(session, buffer.AsSpan(0, count));
                        remaining -= (uint)count;
                    }

                    if (command == "version" && retained is not null)
                    {
                        RequireDone(VersionPayloadCodec.TryParse(retained.ToArray(), out var peerVersion, out _));
                        evidence.PeerProtocolVersion = peerVersion.ProtocolVersion;
                        evidence.PeerServices = peerVersion.Services;
                        evidence.PeerHeight = peerVersion.StartHeight;
                        evidence.PeerUserAgent = Encoding.ASCII.GetString(peerVersion.UserAgent);
                    }

                    if (command == "reject")
                    {
                        evidence.RejectMessages++;
                    }
                }
            }

            File.Move(candidate, Path.ChangeExtension(candidate, ".wire"));
            evidence.Frames++;
            evidence.ReceivedBytes += headerBytes.Length + (long)header.PayloadLength;
            if (session.HasPendingHeaders)
            {
                RequireDone(session.DrainHeaders(headers, out _));
            }

            if (session.PendingMonetaryValidationCount != 0)
            {
                RequireDone(session.DrainMonetaryValidations(verdicts, out var count));
                evidence.MonetaryRejections += count;
            }

            if (session.HasPendingNotFound)
            {
                RequireDone(session.DrainNotFound(inventory, out var count));
                for (var index = 0; index < count; index++)
                {
                    if (inventory[index].Type == 1 && requested.Contains(inventory[index].Hash))
                    {
                        evidence.RequestedNotFound++;
                    }
                }
            }

            if (session.HasPendingInventory)
            {
                RequireDone(session.DrainInventory(inventory, out var count));
                evidence.InventoryMessages++;
                if (evidence.MempoolRequests == 0)
                {
                    evidence.InventoryBeforeRequest += count;
                }
                else
                {
                    evidence.FirstInventoryAfterRequestMilliseconds ??= started.ElapsedMilliseconds - evidence.RequestAtMilliseconds;
                }

                for (var index = 0; index < count; index++)
                {
                    var vector = inventory[index];
                    if (vector.Type != 1)
                    {
                        continue;
                    }

                    evidence.TransactionAnnouncements++;
                    if (!seen.Contains(vector.Hash) && seen.Count == MaximumInventory)
                    {
                        throw new InvalidDataException("Probe unique inventory budget exceeded.");
                    }

                    if (!seen.Add(vector.Hash))
                    {
                        evidence.RepeatedAnnouncements++;
                    }

                    if (evidence.HandshakeReady && (evidence.MempoolRequests != 0 || options.Relay) &&
                        requested.Count < MaximumSampleTransactions && requested.Add(vector.Hash))
                    {
                        RequireDone(session.RequestTransaction(vector.Hash));
                        while (session.TryGetWrite(out var write))
                        {
                            await stream.WriteAsync(write.Bytes, cancellationToken).ConfigureAwait(false);
                            RequireDone(session.AcknowledgeWrite(write, write.Bytes.Length));
                        }

                        sink.Requested.Add(vector.Hash);
                        evidence.RequestedTransactions++;
                    }
                }

                evidence.UniqueTransactionIds = seen.Count;
            }
        }
    }

    private static void Consume(BsvPeerObservationSession session, ReadOnlySpan<byte> bytes)
    {
        var status = session.Consume(bytes, out var consumed);
        if (consumed != bytes.Length || status is not (OperationStatus.Done or OperationStatus.NeedMoreData))
        {
            throw new InvalidDataException("Core rejected probe ingress.");
        }
    }

    private static void RequireDone(OperationStatus status)
    {
        if (status != OperationStatus.Done)
        {
            throw new InvalidDataException($"Probe protocol operation failed: {status}.");
        }
    }

    private sealed class SampleSink(MempoolEvidence evidence) : ILegacyTransactionSink
    {
        internal HashSet<Hash256> Requested { get; } = [];
        public void OnTransactionStarted(int version, ulong inputCount) { }
        public void OnInputStarted(ulong inputIndex, in OutPoint previousOutput, ulong scriptLength) { }
        public void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script) { }
        public void OnInputCompleted(ulong inputIndex, uint sequence) { }
        public void OnOutputsStarted(ulong outputCount) { }
        public void OnOutputStarted(ulong outputIndex, long valueSatoshis, ulong scriptLength) { }
        public void OnOutputScriptChunk(ulong outputIndex, ReadOnlySpan<byte> script) { }
        public void OnOutputCompleted(ulong outputIndex) { }
        public void OnTransactionAborted() { }
        public void OnTransactionCommitted(in LegacyTransactionSummary summary)
        {
            evidence.ValidatedTransactions++;
            if (Requested.Contains(summary.TransactionId))
            {
                evidence.ValidatedRequestedTransactions++;
            }
        }
    }
}

internal sealed class MempoolEvidence(string peer, bool relay, int seconds)
{
    public int SchemaVersion { get; } = 1;
    public string Peer { get; } = peer;
    public string? RepositoryCommit { get; set; }
    public string? RepositoryState { get; set; }
    public bool Relay { get; } = relay;
    public bool RequestMempool { get; set; } = true;
    public bool HandshakeReady { get; set; }
    public int DurationLimitSeconds { get; } = seconds;
    public DateTimeOffset StartedAt { get; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? FinishedAt { get; set; }
    public string EndReason { get; set; } = "running";
    public string? Failure { get; set; }
    public bool CompleteMempoolClaim { get; }
    public bool TransactionBroadcast { get; }
    public int PeerProtocolVersion { get; set; }
    public ulong PeerServices { get; set; }
    public int PeerHeight { get; set; }
    public string? PeerUserAgent { get; set; }
    public int MempoolRequests { get; set; }
    public long RequestAtMilliseconds { get; set; }
    public long? FirstInventoryAfterRequestMilliseconds { get; set; }
    public long ReceivedBytes { get; set; }
    public int Frames { get; set; }
    public int InventoryMessages { get; set; }
    public int InventoryBeforeRequest { get; set; }
    public long TransactionAnnouncements { get; set; }
    public int UniqueTransactionIds { get; set; }
    public long RepeatedAnnouncements { get; set; }
    public int RequestedTransactions { get; set; }
    public int RequestedNotFound { get; set; }
    public int ValidatedTransactions { get; set; }
    public int ValidatedRequestedTransactions { get; set; }
    public int MonetaryRejections { get; set; }
    public int RejectMessages { get; set; }
}
