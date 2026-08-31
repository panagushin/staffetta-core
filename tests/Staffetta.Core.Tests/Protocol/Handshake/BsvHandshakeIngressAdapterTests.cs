using System.Buffers;
using System.Buffers.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Tests.Protocol.Handshake;

[TestClass]
public sealed class BsvHandshakeIngressAdapterTests
{
    private const int MinimumProtocolVersion = VersionPayloadCodec.CurrentProtocolVersion;
    private const ulong LocalNonce = 0x0102_0304_0506_0708;
    private const ulong PeerNonce = 0x1112_1314_1516_1718;
    private const ulong MaximumPayloadLength = 4 * 1024 * 1024;

    private static readonly byte[] NetworkMagic = [0xe3, 0xe1, 0xf3, 0xe8];

    [TestMethod]
    public void ConcatenatedHandshakeAndPingCompleteAtEverySplitBoundary()
    {
        var versionFrame = EncodeBasic("version"u8, CreateVersionPayload(PeerNonce));
        var verackFrame = EncodeBasic("verack"u8, []);
        Span<byte> pingPayload = stackalloc byte[ModernPingPongPayloadCodec.EncodedLength];
        Assert.AreEqual(
            OperationStatus.Done,
            ModernPingPongPayloadCodec.TryWrite(pingPayload, 42, out _));
        var pingFrame = EncodeBasic("ping"u8, pingPayload);
        var source = versionFrame.Concat(verackFrame).Concat(pingFrame).ToArray();

        for (var split = 0; split <= source.Length; split++)
        {
            using var adapter = CreateStartedAdapter(out var outputs);
            var observed = new List<BsvHandshakeOutput>();

            ConsumeAvailable(adapter, source.AsSpan(0, split), observed, outputs);
            ConsumeAvailable(adapter, source.AsSpan(split), observed, outputs);

            Assert.AreEqual(BsvHandshakeState.Ready, adapter.Handshake.State, $"split {split}");
            Assert.IsTrue(adapter.Handshake.HasPeerVersion, $"split {split}");
            Assert.IsTrue(adapter.Handshake.HasPeerVerack, $"split {split}");
            CollectionAssert.AreEqual(
                new[]
                {
                    new BsvHandshakeOutput(BsvHandshakeOutputKind.SendVerack),
                    new BsvHandshakeOutput(BsvHandshakeOutputKind.SendProtoconf),
                    new BsvHandshakeOutput(BsvHandshakeOutputKind.BecameReady),
                    new BsvHandshakeOutput(BsvHandshakeOutputKind.SendPong, 42),
                },
                observed,
                $"split {split}");
        }
    }

    [TestMethod]
    public void OutputsBlockInputAndDrainAtomically()
    {
        using var adapter = new BsvHandshakeIngressAdapter(
            NetworkMagic,
            MaximumPayloadLength,
            MinimumProtocolVersion);
        Assert.AreEqual(OperationStatus.Done, adapter.Start(LocalNonce));
        Assert.AreEqual(1, adapter.PendingOutputCount);
        Assert.AreEqual(OperationStatus.DestinationTooSmall, adapter.Start(LocalNonce + 1));
        Assert.AreEqual(1, adapter.PendingOutputCount);

        var versionFrame = EncodeBasic("version"u8, CreateVersionPayload(PeerNonce));
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            adapter.Consume(versionFrame, out var blockedConsumed));
        Assert.AreEqual(0, blockedConsumed);

        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            adapter.DrainOutputs([], out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.AreEqual(1, adapter.PendingOutputCount);

        Span<BsvHandshakeOutput> outputs = stackalloc BsvHandshakeOutput[3];
        Assert.AreEqual(OperationStatus.Done, adapter.DrainOutputs(outputs, out var startWritten));
        Assert.AreEqual(1, startWritten);
        Assert.AreEqual(BsvHandshakeOutputKind.SendVersion, outputs[0].Kind);

        Assert.AreEqual(
            OperationStatus.Done,
            adapter.Consume(versionFrame, out var versionConsumed));
        Assert.AreEqual(versionFrame.Length, versionConsumed);
        Assert.AreEqual(2, adapter.PendingOutputCount);

        outputs.Fill(new BsvHandshakeOutput((BsvHandshakeOutputKind)byte.MaxValue, ulong.MaxValue));
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            adapter.DrainOutputs(outputs[..1], out shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.AreEqual((BsvHandshakeOutputKind)byte.MaxValue, outputs[0].Kind);
        Assert.AreEqual(2, adapter.PendingOutputCount);

        Assert.AreEqual(OperationStatus.Done, adapter.DrainOutputs(outputs, out var versionWritten));
        Assert.AreEqual(2, versionWritten);
        Assert.AreEqual(BsvHandshakeOutputKind.SendVerack, outputs[0].Kind);
        Assert.AreEqual(BsvHandshakeOutputKind.SendProtoconf, outputs[1].Kind);
    }

    [TestMethod]
    public void BadChecksumAbortsWithoutHandshakeEffectsOrReplay()
    {
        using var adapter = CreateStartedAdapter(out _);
        var payload = CreateVersionPayload(PeerNonce);
        var frame = EncodeBasic("version"u8, payload);
        frame[^1] ^= 0xff;

        Assert.AreEqual(OperationStatus.InvalidData, adapter.Consume(frame, out var bytesConsumed));
        Assert.AreEqual(frame.Length, bytesConsumed);
        Assert.AreEqual(BsvHandshakeState.Negotiating, adapter.Handshake.State);
        Assert.IsFalse(adapter.Handshake.HasPeerVersion);
        Assert.AreEqual(0, adapter.PendingOutputCount);

        Assert.AreEqual(OperationStatus.InvalidData, adapter.Consume(frame, out var retryConsumed));
        Assert.AreEqual(0, retryConsumed);
        Assert.AreEqual(BsvHandshakeState.Negotiating, adapter.Handshake.State);
        Assert.AreEqual(OperationStatus.InvalidData, adapter.Start(LocalNonce + 1));
    }

    [TestMethod]
    public void MalformedValidatedControlPayloadBecomesWireViolation()
    {
        using var adapter = CreateStartedAdapter(out _);
        var payload = CreateVersionPayload(PeerNonce);
        payload[^1] = 2;
        var frame = EncodeBasic("version"u8, payload);

        Assert.AreEqual(OperationStatus.InvalidData, adapter.Consume(frame, out var bytesConsumed));
        Assert.AreEqual(frame.Length, bytesConsumed);
        Assert.AreEqual(BsvHandshakeState.Terminal, adapter.Handshake.State);
        Assert.AreEqual(BsvHandshakeTerminalReason.WireViolation, adapter.Handshake.TerminalReason);
        Assert.IsFalse(adapter.Handshake.HasPeerVersion);
    }

    [TestMethod]
    public void SemanticFaultConsumesOnlyItsFrameAndNeverReplaysFollowingInput()
    {
        using var adapter = CreateStartedAdapter(out _);
        var payload = CreateVersionPayload(PeerNonce);
        payload[^1] = 2;
        var malformedFrame = EncodeBasic("version"u8, payload);
        var followingFrame = EncodeBasic("verack"u8, []);
        var source = malformedFrame.Concat(followingFrame).ToArray();

        Assert.AreEqual(OperationStatus.InvalidData, adapter.Consume(source, out var bytesConsumed));
        Assert.AreEqual(malformedFrame.Length, bytesConsumed);
        Assert.AreEqual(BsvHandshakeTerminalReason.WireViolation, adapter.Handshake.TerminalReason);

        Assert.AreEqual(
            OperationStatus.InvalidData,
            adapter.Consume(source.AsSpan(bytesConsumed), out var retryConsumed));
        Assert.AreEqual(0, retryConsumed);
        Assert.IsFalse(adapter.Handshake.HasPeerVerack);
    }

    [TestMethod]
    public void CompleteButTruncatedVersionPayloadMapsNeedMoreDataToWireViolation()
    {
        using var adapter = CreateStartedAdapter(out _);
        var truncatedPayload = new byte[VersionPayloadCodec.RequiredPrefixLength + 1];
        BinaryPrimitives.WriteInt32LittleEndian(truncatedPayload, MinimumProtocolVersion);
        var malformedFrame = EncodeBasic("version"u8, truncatedPayload);
        var followingFrame = EncodeBasic("verack"u8, []);
        var source = malformedFrame.Concat(followingFrame).ToArray();

        Assert.AreEqual(OperationStatus.InvalidData, adapter.Consume(source, out var bytesConsumed));
        Assert.AreEqual(malformedFrame.Length, bytesConsumed);
        Assert.AreEqual(BsvHandshakeTerminalReason.WireViolation, adapter.Handshake.TerminalReason);

        Assert.AreEqual(
            OperationStatus.InvalidData,
            adapter.Consume(source.AsSpan(bytesConsumed), out var retryConsumed));
        Assert.AreEqual(0, retryConsumed);
        Assert.IsFalse(adapter.Handshake.HasPeerVerack);
    }

    [TestMethod]
    public void KnownCommandsRejectLengthsAtTheHeaderBoundary()
    {
        var cases = new (byte[] Command, uint PayloadLength)[]
        {
            ("version"u8.ToArray(), 45),
            ("version"u8.ToArray(), 475),
            ("verack"u8.ToArray(), 1),
            ("ping"u8.ToArray(), 7),
            ("ping"u8.ToArray(), 9),
            ("pong"u8.ToArray(), 7),
            ("reject"u8.ToArray(), 2),
            ("reject"u8.ToArray(), 159),
            ("protoconf"u8.ToArray(), 4),
            ("protoconf"u8.ToArray(), 1_048_577),
        };

        foreach (var testCase in cases)
        {
            using var adapter = CreateStartedAdapter(out _);
            var header = EncodeBasicHeader(testCase.Command, testCase.PayloadLength);

            Assert.AreEqual(
                OperationStatus.InvalidData,
                adapter.Consume(header, out var bytesConsumed),
                $"{System.Text.Encoding.ASCII.GetString(testCase.Command)}:{testCase.PayloadLength}");
            Assert.AreEqual(header.Length, bytesConsumed);
            Assert.AreEqual(BsvHandshakeState.Terminal, adapter.Handshake.State);
            Assert.AreEqual(BsvHandshakeTerminalReason.WireViolation, adapter.Handshake.TerminalReason);
        }
    }

    [TestMethod]
    public void MaximumVersionLengthIsAdmittedAtTheHeaderBoundary()
    {
        Assert.AreEqual(474, VersionPayloadCodec.MaximumPayloadLength);
        using var adapter = CreateStartedAdapter(out _);
        var header = EncodeBasicHeader("version"u8, VersionPayloadCodec.MaximumPayloadLength);

        Assert.AreEqual(OperationStatus.NeedMoreData, adapter.Consume(header, out var bytesConsumed));
        Assert.AreEqual(header.Length, bytesConsumed);
        Assert.AreEqual(BsvHandshakeState.Negotiating, adapter.Handshake.State);
    }

    [TestMethod]
    public void ProtoconfStreamingMatchesWholeBufferCodecVectors()
    {
        var maximumPolicy = new byte[1 + sizeof(uint) + 3 + ProtoconfPayloadCodec.MaximumStreamPoliciesLength];
        maximumPolicy[0] = 2;
        BinaryPrimitives.WriteUInt32LittleEndian(maximumPolicy.AsSpan(1), 64 * 1024 * 1024);
        maximumPolicy[5] = 0xfd;
        BinaryPrimitives.WriteUInt16LittleEndian(maximumPolicy.AsSpan(6), ProtoconfPayloadCodec.MaximumStreamPoliciesLength);

        var vectors = new[]
        {
            new byte[] { 1, 0, 0, 0, 4 },
            new byte[] { 2, 0, 0, 0, 4, 0 },
            new byte[] { 3, 0, 0, 0, 4, 0, 0xaa, 0xbb },
            maximumPolicy,
            new byte[] { 0, 0, 0, 0, 0 },
            new byte[] { 0xfd, 1, 0, 0, 0, 0, 0 },
            new byte[] { 2, 0, 0, 0, 4, 0xfd, 0x8b, 0x02 },
            new byte[] { 1, 0, 0, 0, 4, 0 },
            new byte[] { 2, 0, 0, 0, 4, 0, 0xaa },
        };

        foreach (var vector in vectors)
        {
            var expected = ProtoconfPayloadCodec.TryParse(vector, out _, out _);
            for (var split = 0; split <= vector.Length; split++)
            {
                using var adapter = CreateReadyAdapter();
                var frame = EncodeBasic("protoconf"u8, vector);
                var headerLength = MessageHeaderCodec.BasicHeaderLength;

                var finalStatus = expected == OperationStatus.Done
                    ? OperationStatus.Done
                    : OperationStatus.InvalidData;
                Assert.AreEqual(
                    split == vector.Length ? finalStatus : OperationStatus.NeedMoreData,
                    adapter.Consume(frame.AsSpan(0, headerLength + split), out var firstConsumed));
                Assert.AreEqual(headerLength + split, firstConsumed);

                if (split < vector.Length)
                {
                    var status = adapter.Consume(frame.AsSpan(headerLength + split), out var secondConsumed);
                    Assert.AreEqual(frame.Length - headerLength - split, secondConsumed);
                    Assert.AreEqual(
                        finalStatus,
                        status,
                        $"vector length {vector.Length}, split {split}");
                }

                Assert.AreEqual(
                    expected == OperationStatus.Done
                        ? BsvHandshakeTerminalReason.None
                        : BsvHandshakeTerminalReason.WireViolation,
                    adapter.Handshake.TerminalReason);
            }
        }
    }

    [TestMethod]
    public void NearMaximumProtoconfIsConsumedWithConstantPayloadMemory()
    {
        var payload = new byte[ProtoconfPayloadCodec.MaximumPayloadLength];
        payload[0] = 3;
        BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(1), 64 * 1024 * 1024);
        payload[5] = 0;
        var frame = EncodeBasic("protoconf"u8, payload);
        using var adapter = CreateReadyAdapter();

        Assert.AreEqual(
            OperationStatus.NeedMoreData,
            adapter.Consume(frame.AsSpan(0, MessageHeaderCodec.BasicHeaderLength), out var headerConsumed));
        Assert.AreEqual(MessageHeaderCodec.BasicHeaderLength, headerConsumed);

        _ = adapter.Consume(frame.AsSpan(MessageHeaderCodec.BasicHeaderLength, 1), out _);
        var before = GC.GetAllocatedBytesForCurrentThread();
        var offset = MessageHeaderCodec.BasicHeaderLength + 1;
        OperationStatus status = OperationStatus.NeedMoreData;
        while (offset < frame.Length)
        {
            var length = Math.Min(4096, frame.Length - offset);
            status = adapter.Consume(frame.AsSpan(offset, length), out var consumed);
            Assert.AreEqual(length, consumed);
            offset += consumed;
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.AreEqual(OperationStatus.Done, status);
        Assert.IsTrue(allocated < 16 * 1024, $"Allocated {allocated} bytes while streaming payload.");
        Assert.IsTrue(adapter.Handshake.HasPeerProtoconf);
        Assert.AreEqual<uint>(64 * 1024 * 1024, adapter.Handshake.AdvertisedPeerMaximumReceivePayloadLength);
    }

    [TestMethod]
    public void LargeUnknownPayloadStreamsWithoutHandshakeEffectsOrAllocationSlope()
    {
        var payload = new byte[2 * 1024 * 1024];
        payload.AsSpan().Fill(0x5a);
        var frame = EncodeBasic("unknown"u8, payload);
        using var adapter = CreateStartedAdapter(out _);

        Assert.AreEqual(
            OperationStatus.NeedMoreData,
            adapter.Consume(frame.AsSpan(0, MessageHeaderCodec.BasicHeaderLength), out _));
        _ = adapter.Consume(frame.AsSpan(MessageHeaderCodec.BasicHeaderLength, 1), out _);
        var before = GC.GetAllocatedBytesForCurrentThread();
        var offset = MessageHeaderCodec.BasicHeaderLength + 1;
        OperationStatus status = OperationStatus.NeedMoreData;
        while (offset < frame.Length)
        {
            var length = Math.Min(8192, frame.Length - offset);
            status = adapter.Consume(frame.AsSpan(offset, length), out var consumed);
            Assert.AreEqual(length, consumed);
            offset += consumed;
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.AreEqual(OperationStatus.Done, status);
        Assert.IsTrue(allocated < 16 * 1024, $"Allocated {allocated} bytes while streaming payload.");
        Assert.AreEqual(BsvHandshakeState.Negotiating, adapter.Handshake.State);
        Assert.IsFalse(adapter.Handshake.HasPeerVersion);
        Assert.AreEqual(0, adapter.PendingOutputCount);
    }

    [TestMethod]
    public void EndOfInputAndDisposalHaveExactLifecycle()
    {
        var partialPayloadAdapter = CreateStartedAdapter(out _);
        var versionFrame = EncodeBasic("version"u8, CreateVersionPayload(PeerNonce));
        Assert.AreEqual(
            OperationStatus.NeedMoreData,
            partialPayloadAdapter.Consume(versionFrame.AsSpan(0, versionFrame.Length - 1), out _));
        Assert.AreEqual(OperationStatus.InvalidData, partialPayloadAdapter.CompleteEndOfInput());
        Assert.AreEqual(OperationStatus.InvalidData, partialPayloadAdapter.CompleteEndOfInput());
        Assert.AreEqual(BsvHandshakeState.Negotiating, partialPayloadAdapter.Handshake.State);
        Assert.IsFalse(partialPayloadAdapter.Handshake.HasPeerVersion);
        partialPayloadAdapter.Dispose();

        var cleanAdapter = CreateStartedAdapter(out _);
        Assert.AreEqual(OperationStatus.Done, cleanAdapter.CompleteEndOfInput());
        Assert.AreEqual(OperationStatus.Done, cleanAdapter.CompleteEndOfInput());
        Assert.AreEqual(OperationStatus.InvalidData, cleanAdapter.Consume([], out var consumed));
        Assert.AreEqual(0, consumed);
        cleanAdapter.Dispose();
        Assert.ThrowsException<ObjectDisposedException>(() => cleanAdapter.Start(LocalNonce));
    }

    [TestMethod]
    public void CleanEndOfInputPreservesAlreadyPendingOutputs()
    {
        using var adapter = new BsvHandshakeIngressAdapter(
            NetworkMagic,
            MaximumPayloadLength,
            MinimumProtocolVersion);
        Assert.AreEqual(OperationStatus.Done, adapter.Start(LocalNonce));

        Assert.AreEqual(OperationStatus.Done, adapter.CompleteEndOfInput());
        Assert.AreEqual(1, adapter.PendingOutputCount);

        Span<BsvHandshakeOutput> outputs = stackalloc BsvHandshakeOutput[1];
        Assert.AreEqual(OperationStatus.Done, adapter.DrainOutputs(outputs, out var outputsWritten));
        Assert.AreEqual(1, outputsWritten);
        Assert.AreEqual(BsvHandshakeOutputKind.SendVersion, outputs[0].Kind);
    }

    [TestMethod]
    public void DisposeMidProvisionalPayloadHasNoHandshakeEffect()
    {
        var versionAdapter = CreateStartedAdapter(out var outputs);
        var versionFrame = EncodeBasic("version"u8, CreateVersionPayload(PeerNonce));
        Assert.AreEqual(
            OperationStatus.NeedMoreData,
            versionAdapter.Consume(versionFrame.AsSpan(0, versionFrame.Length - 1), out _));

        versionAdapter.Dispose();
        Assert.AreEqual(BsvHandshakeState.Negotiating, versionAdapter.Handshake.State);
        Assert.IsFalse(versionAdapter.Handshake.HasPeerVersion);
        Assert.ThrowsException<ObjectDisposedException>(() => versionAdapter.Consume([], out _));
        Assert.ThrowsException<ObjectDisposedException>(() => versionAdapter.DrainOutputs(outputs, out _));
        Assert.ThrowsException<ObjectDisposedException>(() => versionAdapter.CompleteEndOfInput());

        var protoconfAdapter = CreateReadyAdapter();
        var protoconfFrame = EncodeBasic("protoconf"u8, [1, 0, 0, 0, 4]);
        Assert.AreEqual(
            OperationStatus.NeedMoreData,
            protoconfAdapter.Consume(protoconfFrame.AsSpan(0, protoconfFrame.Length - 1), out _));

        protoconfAdapter.Dispose();
        Assert.AreEqual(BsvHandshakeState.Ready, protoconfAdapter.Handshake.State);
        Assert.IsFalse(protoconfAdapter.Handshake.HasPeerProtoconf);
    }

    private static BsvHandshakeIngressAdapter CreateStartedAdapter(
        out BsvHandshakeOutput[] outputBuffer)
    {
        var adapter = new BsvHandshakeIngressAdapter(
            NetworkMagic,
            MaximumPayloadLength,
            MinimumProtocolVersion);
        Assert.AreEqual(OperationStatus.Done, adapter.Start(LocalNonce));
        outputBuffer = new BsvHandshakeOutput[BsvHandshakeStateMachine.MaximumOutputCount];
        Assert.AreEqual(OperationStatus.Done, adapter.DrainOutputs(outputBuffer, out var outputsWritten));
        Assert.AreEqual(1, outputsWritten);
        return adapter;
    }

    private static BsvHandshakeIngressAdapter CreateReadyAdapter()
    {
        var adapter = CreateStartedAdapter(out var outputs);
        var versionFrame = EncodeBasic("version"u8, CreateVersionPayload(PeerNonce));
        Assert.AreEqual(OperationStatus.Done, adapter.Consume(versionFrame, out _));
        Assert.AreEqual(OperationStatus.Done, adapter.DrainOutputs(outputs, out var versionOutputs));
        Assert.AreEqual(2, versionOutputs);
        var verackFrame = EncodeBasic("verack"u8, []);
        Assert.AreEqual(OperationStatus.Done, adapter.Consume(verackFrame, out _));
        Assert.AreEqual(OperationStatus.Done, adapter.DrainOutputs(outputs, out var verackOutputs));
        Assert.AreEqual(1, verackOutputs);
        Assert.AreEqual(BsvHandshakeState.Ready, adapter.Handshake.State);
        return adapter;
    }

    private static void ConsumeAvailable(
        BsvHandshakeIngressAdapter adapter,
        ReadOnlySpan<byte> source,
        List<BsvHandshakeOutput> observed,
        BsvHandshakeOutput[] outputBuffer)
    {
        var offset = 0;
        do
        {
            var status = adapter.Consume(source[offset..], out var consumed);
            Assert.AreNotEqual(OperationStatus.InvalidData, status);
            Assert.AreNotEqual(OperationStatus.DestinationTooSmall, status);
            offset += consumed;
            if (adapter.PendingOutputCount > 0)
            {
                Assert.AreEqual(
                    OperationStatus.Done,
                    adapter.DrainOutputs(outputBuffer, out var outputsWritten));
                for (var index = 0; index < outputsWritten; index++)
                {
                    observed.Add(outputBuffer[index]);
                }
            }

            if (status == OperationStatus.NeedMoreData)
            {
                break;
            }
        }
        while (offset < source.Length);
    }

    private static byte[] CreateVersionPayload(ulong nonce)
    {
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [192, 0, 2, 1], 8_333, out var receiving));
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [192, 0, 2, 2], 8_333, out var source));
        var version = new VersionPayload(
            MinimumProtocolVersion,
            services: 1,
            timestampUnixSeconds: 1_788_131_200,
            receiving,
            source,
            nonce,
            "/Staffetta:test/"u8,
            startHeight: 948_321,
            relay: true);
        var payload = new byte[BsvHandshakeIngressAdapter.MaximumStagedPayloadLength];
        Assert.AreEqual(OperationStatus.Done, VersionPayloadCodec.TryWrite(payload, version, out var bytesWritten));
        return payload[..bytesWritten];
    }

    private static byte[] EncodeBasic(ReadOnlySpan<byte> command, ReadOnlySpan<byte> payload)
    {
        var checksum = MessageChecksum.Compute(payload);
        Span<byte> checksumBytes = stackalloc byte[MessageChecksum.Length];
        Assert.AreEqual(OperationStatus.Done, checksum.TryCopyTo(checksumBytes, out _));
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic(command, (uint)payload.Length, checksumBytes, out var header));
        var frame = new byte[MessageHeaderCodec.BasicHeaderLength + payload.Length];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(frame, NetworkMagic, header, MaximumPayloadLength, out var headerLength));
        payload.CopyTo(frame.AsSpan(headerLength));
        return frame;
    }

    private static byte[] EncodeBasicHeader(ReadOnlySpan<byte> command, uint payloadLength)
    {
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic(command, payloadLength, [0, 0, 0, 0], out var header));
        var destination = new byte[MessageHeaderCodec.BasicHeaderLength];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(
                destination,
                NetworkMagic,
                header,
                MaximumPayloadLength,
                out var bytesWritten));
        Assert.AreEqual(destination.Length, bytesWritten);
        return destination;
    }
}
