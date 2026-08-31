using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Bsv.LiveProbe.Tests;

[TestClass]
public sealed class LiveProbeSessionTests
{
    private static readonly string[] ExpectedOutboundCommands =
        ["version", "verack", "protoconf", "ping", "getheaders", "pong"];

    private const string ActualLocator =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    [TestMethod]
    public async Task InMemoryPeerProvesCompleteCommandOrderAndAtomicPublication()
    {
        var output = CreateOutputPath();
        try
        {
            var options = ParseOptions(output);
            await using var artifact = CandidateArtifact.Create(output);
            await using var peer = new ScriptedPeerStream(GetFixturePayload());

            await LiveProbe.RunConnectedSessionAsync(
                options,
                peer,
                new IPEndPoint(IPAddress.Parse("192.0.2.10"), 50_000),
                options.Peer,
                artifact,
                new RepositorySnapshot("test-commit", "clean"),
                DateTimeOffset.UnixEpoch,
                new Dictionary<string, long>(StringComparer.Ordinal),
                CancellationToken.None);

            CollectionAssert.AreEqual(
                ExpectedOutboundCommands,
                peer.OutboundCommands);
            Assert.AreEqual(1, peer.OutboundCommands.Count(command => command == "getheaders"));
            Assert.IsFalse(peer.OutboundCommands.Any(command => command is "tx" or "inv"));
            Assert.IsTrue(peer.OutboundVersionRelay.HasValue);
            Assert.IsFalse(peer.OutboundVersionRelay.Value);
            Assert.AreEqual(VersionPayloadCodec.CurrentProtocolVersion, peer.OutboundProtocolVersion);
            Assert.AreEqual<uint>(ProbeWireEncoder.AdvertisedReceiveLimit, peer.OutboundProtoconfLimit);
            Assert.AreEqual("Default", peer.OutboundStreamPolicy);

            Assert.IsTrue(File.Exists(Path.Combine(output, "candidate.bin")));
            Assert.IsTrue(File.Exists(Path.Combine(output, "candidate.json")));
            Assert.IsFalse(Directory.Exists(output + ".part"));
            var manifest = await File.ReadAllTextAsync(Path.Combine(output, "candidate.json"));
            StringAssert.Contains(manifest, "\"PeerProtocolVersion\":70015");
            StringAssert.Contains(manifest, "\"ping\"");
            StringAssert.Contains(manifest, "\"headers\"");
            Assert.IsFalse(manifest.Contains("192.0.2.10:50000", StringComparison.Ordinal));
        }
        finally
        {
            DeleteTestPaths(output);
        }
    }

    [TestMethod]
    public async Task EndOfInputDuringHandshakeNeverPublishesFinalDirectory()
    {
        var output = CreateOutputPath();
        try
        {
            var options = ParseOptions(output);
            await using var artifact = CandidateArtifact.Create(output);
            await using var peer = new EndOfInputStream();

            await Assert.ThrowsExceptionAsync<EndOfStreamException>(() =>
                LiveProbe.RunConnectedSessionAsync(
                    options,
                    peer,
                    new IPEndPoint(IPAddress.Parse("192.0.2.10"), 50_000),
                    options.Peer,
                    artifact,
                    new RepositorySnapshot("test-commit", "clean"),
                    DateTimeOffset.UnixEpoch,
                    new Dictionary<string, long>(StringComparer.Ordinal),
                    CancellationToken.None));

            Assert.IsFalse(Directory.Exists(output));
            Assert.IsTrue(Directory.Exists(output + ".part"));
            Assert.IsFalse(File.Exists(Path.Combine(output + ".part", "candidate.bin")));
            Assert.IsFalse(File.Exists(Path.Combine(output + ".part", "candidate.json")));
        }
        finally
        {
            DeleteTestPaths(output);
        }
    }

    [TestMethod]
    public async Task CancellationInterruptsBlockedReadWithoutPublishingFinalDirectory()
    {
        var output = CreateOutputPath();
        try
        {
            var options = ParseOptions(output);
            await using var artifact = CandidateArtifact.Create(output);
            await using var peer = new BlockingReadStream();
            using var cancellation = new CancellationTokenSource();

            var run = LiveProbe.RunConnectedSessionAsync(
                options,
                peer,
                new IPEndPoint(IPAddress.Parse("192.0.2.10"), 50_000),
                options.Peer,
                artifact,
                new RepositorySnapshot("test-commit", "clean"),
                DateTimeOffset.UnixEpoch,
                new Dictionary<string, long>(StringComparer.Ordinal),
                cancellation.Token);
            await peer.ReadEntered;
            cancellation.Cancel();
            await Assert.ThrowsExceptionAsync<TimeoutException>(async () => await run);

            Assert.IsFalse(Directory.Exists(output));
            Assert.IsTrue(Directory.Exists(output + ".part"));
            Assert.IsFalse(File.Exists(Path.Combine(output + ".part", "candidate.bin")));
            Assert.IsFalse(File.Exists(Path.Combine(output + ".part", "candidate.json")));
        }
        finally
        {
            DeleteTestPaths(output);
        }
    }

    private static ProbeOptions ParseOptions(string output) => ProbeOptions.Parse(
        ["--peer", "127.0.0.1:8333", "--locator", ActualLocator, "--output", output]);

    private static byte[] GetFixturePayload() => File.ReadAllBytes(Path.Combine(
        AppContext.BaseDirectory,
        "Fixtures",
        "Bsv",
        "headers-mainnet-after-genesis-2000-20260830.bin"));

    private static string CreateOutputPath() => Path.Combine(
        Path.GetTempPath(),
        "staffetta-live-probe-session-tests",
        Guid.NewGuid().ToString("N"),
        "capture");

    private static void DeleteTestPaths(string output)
    {
        if (Directory.Exists(output))
        {
            Directory.Delete(output, recursive: true);
        }

        if (Directory.Exists(output + ".part"))
        {
            Directory.Delete(output + ".part", recursive: true);
        }

        var parent = Directory.GetParent(output)?.FullName;
        if (parent is not null && Directory.Exists(parent))
        {
            Directory.Delete(parent, recursive: true);
        }
    }

    private static byte[] EncodePeerVersion()
    {
        NetworkAddress.TryCreateIpv4(0, [127, 0, 0, 1], 8333, out var address);
        Span<byte> payload = stackalloc byte[VersionPayloadCodec.MaximumPayloadLength];
        var version = new VersionPayload(
            70_015,
            0,
            1_800_000_000,
            address,
            address,
            123,
            "/Bitcoin SV:1.2.2/"u8,
            900_000,
            relay: true);
        Assert.AreEqual(
            OperationStatus.Done,
            VersionPayloadCodec.TryWrite(payload, version, out var payloadLength));
        return EncodeFrame("version"u8, payload[..payloadLength]);
    }

    private static byte[] EncodeFrame(ReadOnlySpan<byte> command, ReadOnlySpan<byte> payload)
    {
        var checksum = MessageChecksum.Compute(payload);
        Span<byte> checksumBytes = stackalloc byte[MessageChecksum.Length];
        Assert.AreEqual(OperationStatus.Done, checksum.TryCopyTo(checksumBytes, out _));
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic(command, checked((uint)payload.Length), checksumBytes, out var header));
        var frame = new byte[MessageHeaderCodec.BasicHeaderLength + payload.Length];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(
                frame,
                ProbeWireEncoder.NetworkMagic,
                header,
                ProbeTransport.MaximumFramePayloadLength,
                out var headerLength));
        payload.CopyTo(frame.AsSpan(headerLength));
        return frame;
    }

    private sealed class ScriptedPeerStream(byte[] headersPayload) : Stream
    {
        private readonly Queue<byte[]> _incoming = new();
        private int _incomingOffset;

        internal List<string> OutboundCommands { get; } = [];

        internal int OutboundProtocolVersion { get; private set; }

        internal bool? OutboundVersionRelay { get; private set; }

        internal uint OutboundProtoconfLimit { get; private set; }

        internal string? OutboundStreamPolicy { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_incoming.Count == 0)
            {
                return ValueTask.FromResult(0);
            }

            var segment = _incoming.Peek();
            var count = Math.Min(Math.Min(buffer.Length, 17), segment.Length - _incomingOffset);
            segment.AsSpan(_incomingOffset, count).CopyTo(buffer.Span);
            _incomingOffset += count;
            if (_incomingOffset == segment.Length)
            {
                _incoming.Dequeue();
                _incomingOffset = 0;
            }

            return ValueTask.FromResult(count);
        }

        public override void Write(byte[] buffer, int offset, int count) =>
            ObserveOutbound(buffer.AsSpan(offset, count));

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObserveOutbound(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        private void ObserveOutbound(ReadOnlySpan<byte> frame)
        {
            Assert.AreEqual(
                OperationStatus.Done,
                MessageHeaderCodec.TryParse(
                    frame,
                    ProbeWireEncoder.NetworkMagic,
                    ProbeTransport.MaximumFramePayloadLength,
                    out var header,
                    out var headerLength));
            var commandBytes = new byte[header.Command.Length];
            Assert.AreEqual(OperationStatus.Done, header.Command.TryCopyTo(commandBytes, out _));
            var command = System.Text.Encoding.ASCII.GetString(commandBytes);
            var payload = frame[headerLength..];
            Assert.AreEqual((ulong)payload.Length, header.PayloadLength);
            Assert.AreEqual(MessageChecksum.Compute(payload), header.PayloadChecksum);
            Assert.IsTrue(command is "version" or "verack" or "protoconf" or "ping" or "getheaders" or "pong");
            OutboundCommands.Add(command);

            switch (command)
            {
                case "version":
                    Assert.AreEqual(
                        OperationStatus.Done,
                        VersionPayloadCodec.TryParse(payload, out var version, out _));
                    OutboundProtocolVersion = version.ProtocolVersion;
                    OutboundVersionRelay = version.Relay;
                    _incoming.Enqueue(EncodePeerVersion());
                    _incoming.Enqueue(ProbeWireEncoder.EncodeVerack());
                    break;
                case "protoconf":
                    Assert.AreEqual(
                        OperationStatus.Done,
                        ProtoconfPayloadCodec.TryParse(payload, out var protoconf, out _));
                    OutboundProtoconfLimit = protoconf.MaximumReceivePayloadLength;
                    OutboundStreamPolicy = System.Text.Encoding.ASCII.GetString(protoconf.StreamPolicies);
                    break;
                case "ping":
                    Assert.AreEqual(
                        OperationStatus.Done,
                        ModernPingPongPayloadCodec.TryParse(payload, out var pingNonce));
                    _incoming.Enqueue(ProbeWireEncoder.EncodePong(pingNonce));
                    break;
                case "getheaders":
                    _incoming.Enqueue(ProbeWireEncoder.EncodePing(999));
                    _incoming.Enqueue(EncodeFrame("headers"u8, headersPayload));
                    break;
            }
        }
    }

    private sealed class EndOfInputStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => 0;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(0);
        public override void Write(byte[] buffer, int offset, int count) { }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;
        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private sealed class BlockingReadStream : Stream
    {
        private readonly TaskCompletionSource _readEntered =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal Task ReadEntered => _readEntered.Task;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            _readEntered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }

        public override void Write(byte[] buffer, int offset, int count) { }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;
        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
