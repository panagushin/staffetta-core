using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Staffetta.Core.Protocol.Handshake;

namespace Staffetta.Bsv.LiveProbe;

internal static class LiveProbe
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan PingTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan HeadersTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan TotalTimeout = TimeSpan.FromSeconds(75);

    internal static async Task RunAsync(ProbeOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        var startedUtc = DateTimeOffset.UtcNow;
        var durations = new Dictionary<string, long>(StringComparer.Ordinal);
        await using var artifact = CandidateArtifact.Create(options.OutputDirectory);
        using var totalCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        totalCancellation.CancelAfter(TotalTimeout);
        var repository = await RepositorySnapshot.ReadAsync(totalCancellation.Token).ConfigureAwait(false);
        using var client = new TcpClient(AddressFamily.InterNetwork);

        await RunPhaseAsync(
            "connect",
            ConnectTimeout,
            durations,
            token => client.ConnectAsync(options.Peer, token).AsTask(),
            totalCancellation.Token).ConfigureAwait(false);

        var stream = client.GetStream();
        var localEndpoint = client.Client.LocalEndPoint as IPEndPoint ??
            throw new IOException("The connected socket did not expose an IPv4 local endpoint.");
        await RunConnectedSessionAsync(
            options,
            stream,
            localEndpoint,
            options.Peer,
            artifact,
            repository,
            startedUtc,
            durations,
            totalCancellation.Token).ConfigureAwait(false);
    }

    internal static async Task RunConnectedSessionAsync(
        ProbeOptions options,
        Stream stream,
        IPEndPoint localEndpoint,
        IPEndPoint resolvedRemote,
        CandidateArtifact artifact,
        RepositorySnapshot repository,
        DateTimeOffset startedUtc,
        Dictionary<string, long> durations,
        CancellationToken cancellationToken)
    {
        var session = new SessionEvidence();
        var remoteAddress = CreateNetworkAddress(resolvedRemote);
        var localAddress = CreateNetworkAddress(localEndpoint);
        var localNonce = CreateNonce();

        using var adapter = new BsvHandshakeIngressAdapter(
            ProbeWireEncoder.NetworkMagic,
            ProbeTransport.MaximumFramePayloadLength,
            ProbeWireEncoder.MinimumAcceptedPeerProtocolVersion);
        var startStatus = adapter.Start(localNonce);
        EnsureDone(startStatus, "handshake start");
        await SendPendingOutputsAsync(
            adapter,
            stream,
            remoteAddress,
            localAddress,
            localNonce,
            session,
            cancellationToken).ConfigureAwait(false);

        await RunPhaseAsync(
            "handshake",
            HandshakeTimeout,
            durations,
            async token =>
            {
                while (adapter.Handshake.State != BsvHandshakeState.Ready)
                {
                    var frame = await ProbeTransport.ReceiveFrameAsync(stream, adapter, null, token)
                        .ConfigureAwait(false);
                    session.ObserveCommand(frame.Command);
                    ObserveVersion(frame, session);
                    await SendPendingOutputsAsync(
                        adapter,
                        stream,
                        remoteAddress,
                        localAddress,
                        localNonce,
                        session,
                        token).ConfigureAwait(false);
                    EnsureNegotiating(adapter);
                }
            },
            cancellationToken).ConfigureAwait(false);

        var pingNonce = CreateNonce();
        await RunPhaseAsync(
            "ping",
            PingTimeout,
            durations,
            async token =>
            {
                var output = new BsvHandshakeOutput[1];
                EnsureDone(
                    adapter.Handshake.TryBeginPing(pingNonce, output, out var outputsWritten),
                    "ping start");
                if (outputsWritten != 1 || output[0].Kind != BsvHandshakeOutputKind.SendPing)
                {
                    throw new InvalidDataException("The handshake emitted an invalid ping intent.");
                }

                await ProbeTransport.SendAsync(stream, ProbeWireEncoder.EncodePing(pingNonce), token)
                    .ConfigureAwait(false);
                while (adapter.Handshake.HasPendingPing)
                {
                    var frame = await ProbeTransport.ReceiveFrameAsync(stream, adapter, null, token)
                        .ConfigureAwait(false);
                    session.ObserveCommand(frame.Command);
                    ObserveVersion(frame, session);
                    await SendPendingOutputsAsync(
                        adapter,
                        stream,
                        remoteAddress,
                        localAddress,
                        localNonce,
                        session,
                        token).ConfigureAwait(false);
                    EnsureReady(adapter);
                }
            },
            cancellationToken).ConfigureAwait(false);

        await RunPhaseAsync(
            "headers",
            HeadersTimeout,
            durations,
            async token =>
            {
                await ProbeTransport.SendAsync(
                    stream,
                    ProbeWireEncoder.EncodeGetHeaders(options.Locator),
                    token).ConfigureAwait(false);
                while (true)
                {
                    var frame = await ProbeTransport.ReceiveFrameAsync(
                        stream,
                        adapter,
                        artifact.Stream,
                        token).ConfigureAwait(false);
                    session.ObserveCommand(frame.Command);
                    ObserveVersion(frame, session);
                    await SendPendingOutputsAsync(
                        adapter,
                        stream,
                        remoteAddress,
                        localAddress,
                        localNonce,
                        session,
                        token).ConfigureAwait(false);
                    EnsureReady(adapter);
                    if (frame.CapturedHeaders)
                    {
                        break;
                    }
                }
            },
            cancellationToken).ConfigureAwait(false);

        var headers = await artifact.ValidateAsync(options.Locator, cancellationToken)
            .ConfigureAwait(false);
        var completedUtc = DateTimeOffset.UtcNow;
        var manifest = CreateManifest(
            options,
            repository,
            startedUtc,
            completedUtc,
            durations,
            adapter,
            session,
            headers,
            resolvedRemote);
        await artifact.PublishAsync(manifest, cancellationToken).ConfigureAwait(false);
    }

    private static async Task SendPendingOutputsAsync(
        BsvHandshakeIngressAdapter adapter,
        Stream stream,
        NetworkAddress remoteAddress,
        NetworkAddress localAddress,
        ulong localNonce,
        SessionEvidence evidence,
        CancellationToken cancellationToken)
    {
        var outputs = new BsvHandshakeOutput[BsvHandshakeStateMachine.MaximumOutputCount];
        EnsureDone(adapter.DrainOutputs(outputs, out var count), "output drain");
        for (var index = 0; index < count; index++)
        {
            byte[]? frame = outputs[index].Kind switch
            {
                BsvHandshakeOutputKind.SendVersion => ProbeWireEncoder.EncodeVersion(
                    remoteAddress,
                    localAddress,
                    DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    localNonce),
                BsvHandshakeOutputKind.SendVerack => ProbeWireEncoder.EncodeVerack(),
                BsvHandshakeOutputKind.SendProtoconf => ProbeWireEncoder.EncodeProtoconf(),
                BsvHandshakeOutputKind.SendPong => ProbeWireEncoder.EncodePong(outputs[index].Value),
                BsvHandshakeOutputKind.BecameReady => null,
                BsvHandshakeOutputKind.PingAcknowledged => null,
                BsvHandshakeOutputKind.ForwardReject => throw new InvalidDataException(
                    "The peer sent a reject message."),
                BsvHandshakeOutputKind.SendPing => throw new InvalidDataException(
                    "Ping intents must be initiated and serialized by the probe."),
                _ => throw new InvalidDataException("The handshake emitted an unknown output."),
            };

            if (outputs[index].Kind == BsvHandshakeOutputKind.SendPong)
            {
                evidence.ObservedPeerPing = true;
            }

            if (outputs[index].Kind == BsvHandshakeOutputKind.PingAcknowledged)
            {
                evidence.PingAcknowledged = true;
            }

            if (frame is not null)
            {
                await ProbeTransport.SendAsync(stream, frame, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static void ObserveVersion(ReceivedFrame frame, SessionEvidence evidence)
    {
        if (frame.Command == "verack")
        {
            evidence.VerackCount++;
            return;
        }

        if (frame.Command != "version" || evidence.PeerUserAgent is not null)
        {
            return;
        }

        var status = VersionPayloadCodec.TryParse(
            frame.RetainedPayload,
            out var version,
            out var bytesConsumed);
        if (status != OperationStatus.Done || bytesConsumed != frame.RetainedPayload.Length)
        {
            throw new InvalidDataException("The retained peer version payload was not canonical.");
        }

        evidence.PeerUserAgent = DescribeUserAgent(version.UserAgent);
        evidence.RelayObservation = version.HasRelay
            ? version.Relay ? "observed_true" : "observed_false"
            : "absent";
    }

    private static PeerUserAgent DescribeUserAgent(ReadOnlySpan<byte> userAgent)
    {
        var safeAscii = true;
        foreach (var value in userAgent)
        {
            if (value is < 0x20 or > 0x7e)
            {
                safeAscii = false;
                break;
            }
        }

        return new PeerUserAgent(
            safeAscii ? Encoding.ASCII.GetString(userAgent) : null,
            userAgent.Length,
            Convert.ToHexStringLower(SHA256.HashData(userAgent)));
    }

    private static ProbeManifest CreateManifest(
        ProbeOptions options,
        RepositorySnapshot repository,
        DateTimeOffset startedUtc,
        DateTimeOffset completedUtc,
        IReadOnlyDictionary<string, long> durations,
        BsvHandshakeIngressAdapter adapter,
        SessionEvidence session,
        HeadersEvidence headers,
        IPEndPoint resolvedRemote) =>
        new(
            Schema: 1,
            repository.Commit,
            repository.State,
            RuntimeInformation.FrameworkDescription,
            RuntimeInformation.OSDescription,
            options.Peer.ToString(),
            resolvedRemote.ToString(),
            startedUtc,
            completedUtc,
            durations,
            adapter.Handshake.PeerProtocolVersion,
            session.PeerUserAgent ?? new PeerUserAgent(null, 0, Convert.ToHexStringLower(SHA256.HashData([]))),
            options.LocatorHex,
            session.ObservedCommandCount,
            session.ObservedCommandsTruncated,
            session.ObservedCommands,
            new N2Observations(
                session.RelayObservation,
                session.VerackCount > 1 ? "observed_and_tolerated" : "not_observed",
                "not_stimulated_by_policy",
                "validated_exact",
                session.ObservedPeerPing ? "validated_peer_ping_and_pong" : "validated_probe_ping_and_peer_pong"),
            headers,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["normal_handshake"] = "executed",
                ["ping_round_trip"] = session.PingAcknowledged ? "executed" : "failed",
                ["headers_request"] = "executed_once",
                ["malformed_peer_traffic"] = "not_run_by_policy",
                ["transaction_broadcast"] = "not_run_by_policy",
            });

    private static async Task RunPhaseAsync(
        string name,
        TimeSpan timeout,
        Dictionary<string, long> durations,
        Func<CancellationToken, Task> action,
        CancellationToken totalCancellationToken)
    {
        using var phaseCancellation = CancellationTokenSource.CreateLinkedTokenSource(totalCancellationToken);
        phaseCancellation.CancelAfter(timeout);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            await action(phaseCancellation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception) when (phaseCancellation.IsCancellationRequested)
        {
            throw new TimeoutException($"The {name} phase exceeded its deadline.", exception);
        }
        finally
        {
            durations[name] = stopwatch.ElapsedMilliseconds;
        }
    }

    private static NetworkAddress CreateNetworkAddress(IPEndPoint endpoint)
    {
        if (!NetworkAddress.TryCreateIpv4(0, endpoint.Address.GetAddressBytes(), checked((ushort)endpoint.Port), out var address))
        {
            throw new IOException("The connected endpoint was not IPv4.");
        }

        return address;
    }

    private static ulong CreateNonce()
    {
        Span<byte> bytes = stackalloc byte[sizeof(ulong)];
        ulong nonce;
        do
        {
            RandomNumberGenerator.Fill(bytes);
            nonce = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(bytes);
        }
        while (nonce == 0);

        return nonce;
    }

    private static void EnsureNegotiating(BsvHandshakeIngressAdapter adapter)
    {
        if (adapter.Handshake.State == BsvHandshakeState.Terminal)
        {
            throw new InvalidDataException(
                $"The handshake terminated: {adapter.Handshake.TerminalReason}.");
        }
    }

    private static void EnsureReady(BsvHandshakeIngressAdapter adapter)
    {
        if (adapter.Handshake.State != BsvHandshakeState.Ready)
        {
            throw new InvalidDataException("The peer session left the ready state.");
        }
    }

    private static void EnsureDone(OperationStatus status, string operation)
    {
        if (status != OperationStatus.Done)
        {
            throw new InvalidDataException($"The {operation} failed with status {status}.");
        }
    }

    private sealed class SessionEvidence
    {
        private const int MaximumObservedCommandSamples = 256;
        private readonly List<string> _observedCommands = new(MaximumObservedCommandSamples);

        internal PeerUserAgent? PeerUserAgent { get; set; }

        internal string RelayObservation { get; set; } = "not_observed";

        internal int VerackCount { get; set; }

        internal bool ObservedPeerPing { get; set; }

        internal bool PingAcknowledged { get; set; }

        internal long ObservedCommandCount { get; private set; }

        internal bool ObservedCommandsTruncated => ObservedCommandCount > _observedCommands.Count;

        internal IReadOnlyList<string> ObservedCommands => _observedCommands;

        internal void ObserveCommand(string command)
        {
            ObservedCommandCount++;
            if (_observedCommands.Count < MaximumObservedCommandSamples)
            {
                _observedCommands.Add(command);
            }
        }
    }
}
