using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Sessions;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Tests.Protocol.Sessions;

[TestClass]
public sealed class BsvPeerSessionHandshakeEgressProvenanceTests
{
    private const ulong LocalNonce = 0x0102_0304_0506_0708;
    private const ulong PeerNonce = 0x1112_1314_1516_1718;
    private const ulong MaximumPayloadLength = 4 * 1024 * 1024;

    private static ReadOnlySpan<byte> Magic => [0xe3, 0xe1, 0xf3, 0xe8];

    [TestMethod]
    public void VersionIntentRequiresSuccessfulDrainAndRetainsHeadAcrossRetry()
    {
        using var first = CreateSession();
        using var second = CreateSession();
        var localVersion = ParseVersion(LocalNonce);
        var wrongVersion = ParseVersion(PeerNonce);
        Assert.AreEqual(OperationStatus.Done, first.StartHandshake(LocalNonce));
        Assert.AreEqual(OperationStatus.Done, second.StartHandshake(LocalNonce));

        Assert.AreEqual(OperationStatus.DestinationTooSmall, first.PlanVersionEgress(localVersion));
        Assert.IsTrue(first.PendingEgressSegment.IsEmpty);
        Assert.AreEqual(0, first.PendingHandshakeEgressIntentCount);
        Assert.AreEqual(OperationStatus.DestinationTooSmall, second.PlanVersionEgress(localVersion));

        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            first.DrainHandshakeOutputs([], out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.AreEqual(1, first.PendingHandshakeOutputCount);
        Assert.AreEqual(0, first.PendingHandshakeEgressIntentCount);

        Span<BsvHandshakeOutput> output = stackalloc BsvHandshakeOutput[1];
        Assert.AreEqual(OperationStatus.Done, first.DrainHandshakeOutputs(output, out var written));
        Assert.AreEqual(1, written);
        Assert.AreEqual(BsvHandshakeOutputKind.SendVersion, output[0].Kind);
        Assert.AreEqual(1, first.PendingHandshakeEgressIntentCount);
        Assert.AreEqual(OperationStatus.InvalidData, first.PlanVersionEgress(wrongVersion));
        Assert.AreEqual(BsvPeerSessionEgressState.Idle, first.EgressState);
        Assert.IsTrue(first.PendingEgressSegment.IsEmpty);
        Assert.AreEqual(1, first.PendingHandshakeEgressIntentCount);

        var peerVersionFrame = EncodeBasic("version"u8, CreateVersionPayload(PeerNonce));
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            first.Consume(peerVersionFrame, out var blockedConsumed));
        Assert.AreEqual(0, blockedConsumed);
        Assert.AreEqual(OperationStatus.Done, first.PlanVersionEgress(localVersion));
        DrainEgress(first);
        Assert.AreEqual(1, first.PendingHandshakeEgressIntentCount);
        Assert.AreEqual(OperationStatus.Done, first.CommitEgressCompletion());
        Assert.AreEqual(0, first.PendingHandshakeEgressIntentCount);
        Assert.AreEqual(OperationStatus.InvalidData, first.PlanVersionEgress(localVersion));
        Assert.IsTrue(first.PendingEgressSegment.IsEmpty);
    }

    [TestMethod]
    public void VerackProtoconfFactsAndPongPreserveExactFifoOrder()
    {
        using var session = CreateSession();
        Assert.AreEqual(OperationStatus.Done, session.StartHandshake(LocalNonce));
        Span<BsvHandshakeOutput> outputs = stackalloc BsvHandshakeOutput[3];
        Assert.AreEqual(OperationStatus.Done, session.DrainHandshakeOutputs(outputs, out _));
        Assert.AreEqual(OperationStatus.Done, session.PlanVersionEgress(ParseVersion(LocalNonce)));
        DrainAndCommit(session);

        Consume(session, EncodeBasic("version"u8, CreateVersionPayload(PeerNonce)));
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            session.DrainHandshakeOutputs(outputs[..1], out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.AreEqual(0, session.PendingHandshakeEgressIntentCount);
        Assert.AreEqual(OperationStatus.Done, session.DrainHandshakeOutputs(outputs, out var written));
        Assert.AreEqual(2, written);
        Assert.AreEqual(BsvHandshakeOutputKind.SendVerack, outputs[0].Kind);
        Assert.AreEqual(BsvHandshakeOutputKind.SendProtoconf, outputs[1].Kind);
        Assert.AreEqual(2, session.PendingHandshakeEgressIntentCount);

        Assert.AreEqual(
            OperationStatus.InvalidData,
            session.PlanProtoconfEgress(1_048_576, default, includeStreamPolicies: false));
        Assert.AreEqual(BsvPeerSessionEgressState.Idle, session.EgressState);
        Assert.AreEqual(OperationStatus.Done, session.PlanNextHandshakeEgress());
        DrainAndCommit(session);
        Assert.AreEqual(1, session.PendingHandshakeEgressIntentCount);
        Assert.AreEqual(OperationStatus.InvalidData, session.PlanNextHandshakeEgress());
        Assert.AreEqual(
            OperationStatus.InvalidData,
            session.PlanProtoconfEgress(1_048_576, "x"u8, includeStreamPolicies: false));
        Assert.AreEqual(BsvPeerSessionEgressState.Idle, session.EgressState);
        Assert.AreEqual(1, session.PendingHandshakeEgressIntentCount);
        Assert.AreEqual(
            OperationStatus.Done,
            session.PlanProtoconfEgress(1_048_576, default, includeStreamPolicies: false));
        DrainAndCommit(session);
        Assert.AreEqual(0, session.PendingHandshakeEgressIntentCount);

        Consume(session, EncodeBasic("verack"u8, []));
        Assert.AreEqual(OperationStatus.Done, session.DrainHandshakeOutputs(outputs, out written));
        Assert.AreEqual(1, written);
        Assert.AreEqual(BsvHandshakeOutputKind.BecameReady, outputs[0].Kind);
        Assert.AreEqual(0, session.PendingHandshakeEgressIntentCount);
        Assert.AreEqual(OperationStatus.InvalidData, session.PlanNextHandshakeEgress());

        const ulong pingNonce = 0xa1a2_a3a4_a5a6_a7a8;
        Span<byte> pingPayload = stackalloc byte[ModernPingPongPayloadCodec.EncodedLength];
        Assert.AreEqual(
            OperationStatus.Done,
            ModernPingPongPayloadCodec.TryWrite(pingPayload, pingNonce, out _));
        Consume(session, EncodeBasic("ping"u8, pingPayload));
        Assert.AreEqual(OperationStatus.Done, session.DrainHandshakeOutputs(outputs, out written));
        Assert.AreEqual(1, written);
        Assert.AreEqual(BsvHandshakeOutputKind.SendPong, outputs[0].Kind);
        Assert.AreEqual(pingNonce, outputs[0].Value);
        Assert.AreEqual(OperationStatus.Done, session.PlanNextHandshakeEgress());
        DrainAndCommit(session);
        Assert.AreEqual(0, session.PendingHandshakeEgressIntentCount);
    }

    [TestMethod]
    public void AbortRetainsProvenanceUntilSessionTerminationClearsIt()
    {
        using var session = CreateSession();
        Assert.AreEqual(OperationStatus.Done, session.StartHandshake(LocalNonce));
        Span<BsvHandshakeOutput> output = stackalloc BsvHandshakeOutput[1];
        Assert.AreEqual(OperationStatus.Done, session.DrainHandshakeOutputs(output, out _));
        Assert.AreEqual(OperationStatus.Done, session.PlanVersionEgress(ParseVersion(LocalNonce)));
        Assert.AreEqual(OperationStatus.Done, session.AbortEgress());
        Assert.AreEqual(1, session.PendingHandshakeEgressIntentCount);
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            session.Consume([], out var consumed));
        Assert.AreEqual(0, consumed);

        Assert.AreEqual(OperationStatus.Done, session.CompleteEndOfInput());
        Assert.AreEqual(0, session.PendingHandshakeEgressIntentCount);
        Assert.AreEqual(OperationStatus.InvalidData, session.PlanNextHandshakeEgress());
    }

    [TestMethod]
    public void WarmIntentQueueHasNoPerCycleAllocationSlopeAndFactsNeverQueue()
    {
        var queue = new BsvHandshakeEgressIntentQueue();
        BsvHandshakeOutput[] outputs =
        [
            new(BsvHandshakeOutputKind.SendVerack),
            new(BsvHandshakeOutputKind.BecameReady),
            new(BsvHandshakeOutputKind.PingAcknowledged),
            new(BsvHandshakeOutputKind.ForwardReject),
            new(BsvHandshakeOutputKind.SendProtoconf),
        ];
        for (var index = 0; index < 32; index++)
        {
            RunQueueCycle(queue, outputs);
        }

        var smallAllocated = MeasureQueueCycles(queue, outputs, cycleCount: 1);
        var manyAllocated = MeasureQueueCycles(queue, outputs, cycleCount: 10_000);
        Assert.IsTrue(
            manyAllocated <= smallAllocated + 64,
            $"One cycle allocated {smallAllocated} bytes; 10,000 cycles allocated {manyAllocated} bytes.");
    }

    private static long MeasureQueueCycles(
        BsvHandshakeEgressIntentQueue queue,
        ReadOnlySpan<BsvHandshakeOutput> outputs,
        int cycleCount)
    {
        var before = GC.GetAllocatedBytesForCurrentThread();
        var valid = true;
        for (var index = 0; index < cycleCount; index++)
        {
            valid &= RunQueueCycle(queue, outputs);
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.IsTrue(valid);
        return allocated;
    }

    private static bool RunQueueCycle(
        BsvHandshakeEgressIntentQueue queue,
        ReadOnlySpan<BsvHandshakeOutput> outputs)
    {
        if (!queue.TryEnqueueFromOutputs(outputs) ||
            queue.Count != 2 ||
            !queue.TryPeek(out var first) ||
            first.Kind != BsvHandshakeOutputKind.SendVerack)
        {
            return false;
        }

        if (!queue.TryConsume(first))
        {
            return false;
        }
        if (!queue.TryPeek(out var second) ||
            second.Kind != BsvHandshakeOutputKind.SendProtoconf)
        {
            return false;
        }

        return queue.TryConsume(second) && queue.Count == 0;
    }

    private static BsvPeerSessionIngressAdapter CreateSession() =>
        new(
            Magic,
            MaximumPayloadLength,
            VersionPayloadCodec.CurrentProtocolVersion,
            new NullTransactionSink());

    private static VersionPayload ParseVersion(ulong nonce)
    {
        var encoded = CreateVersionPayload(nonce);
        Assert.AreEqual(
            OperationStatus.Done,
            VersionPayloadCodec.TryParse(encoded, out var version, out var consumed));
        Assert.AreEqual(encoded.Length, consumed);
        return version;
    }

    private static byte[] CreateVersionPayload(ulong nonce)
    {
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [192, 0, 2, 1], 8_333, out var receiving));
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [192, 0, 2, 2], 8_333, out var source));
        var version = new VersionPayload(
            VersionPayloadCodec.CurrentProtocolVersion,
            services: 1,
            timestampUnixSeconds: 1_788_131_200,
            receiving,
            source,
            nonce,
            "/Staffetta:provenance/"u8,
            startHeight: 948_321,
            relay: true);
        var payload = new byte[VersionPayloadCodec.MaximumPayloadLength];
        Assert.AreEqual(OperationStatus.Done, VersionPayloadCodec.TryWrite(payload, version, out var written));
        return payload[..written];
    }

    private static void DrainAndCommit(BsvPeerSessionIngressAdapter session)
    {
        DrainEgress(session);
        Assert.AreEqual(OperationStatus.Done, session.CommitEgressCompletion());
    }

    private static void DrainEgress(BsvPeerSessionIngressAdapter session)
    {
        while (!session.PendingEgressSegment.IsEmpty)
        {
            var pending = session.PendingEgressSegment;
            Assert.AreEqual(OperationStatus.Done, session.AcknowledgeEgress(pending, pending.Length));
        }
    }

    private static void Consume(
        BsvPeerSessionIngressAdapter session,
        ReadOnlySpan<byte> frame)
    {
        Assert.AreEqual(OperationStatus.Done, session.Consume(frame, out var consumed));
        Assert.AreEqual(frame.Length, consumed);
    }

    private static byte[] EncodeBasic(ReadOnlySpan<byte> command, ReadOnlySpan<byte> payload)
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
            MessageHeaderCodec.TryWrite(frame, Magic, header, MaximumPayloadLength, out var headerLength));
        payload.CopyTo(frame.AsSpan(headerLength));
        return frame;
    }

    private sealed class NullTransactionSink : ILegacyTransactionSink
    {
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
