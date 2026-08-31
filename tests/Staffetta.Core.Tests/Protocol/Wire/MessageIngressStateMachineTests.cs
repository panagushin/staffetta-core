using System.Buffers;
using System.Buffers.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Tests.Protocol.Wire;

[TestClass]
public sealed class MessageIngressStateMachineTests
{
    private const ulong MaximumPayloadLength = 1_000_000;

    private static readonly byte[] NetworkMagic = [0xe3, 0xe1, 0xf3, 0xe8];

    private static readonly byte[] Payload = Enumerable.Range(0, 257)
        .Select(value => (byte)value)
        .ToArray();

    private static readonly string[] TwoMessageEvents =
        ["start:verack", "commit", "start:ping", "payload:4", "commit"];

    private static readonly string[] VerackEvents = ["start:verack", "commit"];

    private static readonly string[] WrongChecksumEvents = ["start:tx", "payload:3", "abort"];

    private static readonly string[] TruncatedPayloadEvents = ["start:tx", "payload:5", "abort"];

    private static readonly string[] HugeExtendedPrefixEvents = ["start:block", "payload:3", "abort"];

    [TestMethod]
    public void BasicFrameCompletesAtEverySplitBoundary()
    {
        var frame = EncodeBasic("tx"u8, Payload, corruptChecksum: false);

        for (var split = 0; split <= frame.Length; split++)
        {
            var sink = new RecordingSink();
            using var ingress = CreateIngress(sink);

            var firstStatus = ingress.Consume(frame.AsSpan(0, split), out var firstConsumed);

            Assert.AreEqual(split, firstConsumed, $"First chunk at split {split}");
            Assert.AreEqual(
                split == frame.Length ? OperationStatus.Done : OperationStatus.NeedMoreData,
                firstStatus,
                $"First chunk at split {split}");

            if (split < frame.Length)
            {
                var secondStatus = ingress.Consume(frame.AsSpan(split), out var secondConsumed);

                Assert.AreEqual(OperationStatus.Done, secondStatus, $"Second chunk at split {split}");
                Assert.AreEqual(frame.Length - split, secondConsumed, $"Second chunk at split {split}");
            }

            AssertCommittedMessage(sink, Payload);
        }
    }

    [TestMethod]
    public void EveryNonEmptyByteWiseConsumeProgressesUntilCommit()
    {
        var frame = EncodeBasic("tx"u8, Payload, corruptChecksum: false);
        var sink = new RecordingSink();
        using var ingress = CreateIngress(sink);

        Assert.AreEqual(
            OperationStatus.NeedMoreData,
            ingress.Consume([], out var emptyConsumed));
        Assert.AreEqual(0, emptyConsumed);

        for (var index = 0; index < frame.Length; index++)
        {
            var status = ingress.Consume(frame.AsSpan(index, 1), out var bytesConsumed);

            Assert.AreEqual(1, bytesConsumed, $"Byte {index}");
            Assert.AreEqual(
                index == frame.Length - 1 ? OperationStatus.Done : OperationStatus.NeedMoreData,
                status,
                $"Byte {index}");
        }

        AssertCommittedMessage(sink, Payload);
    }

    [TestMethod]
    public void ZeroLengthAndFollowingFrameCompleteInOneConsume()
    {
        var emptyFrame = EncodeBasic("verack"u8, [], corruptChecksum: false);
        byte[] secondPayload = [1, 2, 3, 4];
        var secondFrame = EncodeBasic("ping"u8, secondPayload, corruptChecksum: false);
        var source = emptyFrame.Concat(secondFrame).ToArray();
        var sink = new RecordingSink();
        using var ingress = CreateIngress(sink);

        var status = ingress.Consume(source, out var bytesConsumed);

        Assert.AreEqual(OperationStatus.Done, status);
        Assert.AreEqual(source.Length, bytesConsumed);
        CollectionAssert.AreEqual(TwoMessageEvents, sink.Events);
        CollectionAssert.AreEqual(secondPayload, sink.Payload.ToArray());
    }

    [TestMethod]
    public void SingleFrameConsumeLeavesFollowingFrameUntouched()
    {
        var emptyFrame = EncodeBasic("verack"u8, [], corruptChecksum: false);
        byte[] secondPayload = [1, 2, 3, 4];
        var secondFrame = EncodeBasic("ping"u8, secondPayload, corruptChecksum: false);
        var source = emptyFrame.Concat(secondFrame).ToArray();
        var sink = new RecordingSink();
        using var ingress = CreateIngress(sink);

        var firstStatus = ingress.ConsumeSingleFrame(source, out var firstConsumed);

        Assert.AreEqual(OperationStatus.Done, firstStatus);
        Assert.AreEqual(emptyFrame.Length, firstConsumed);
        CollectionAssert.AreEqual(VerackEvents, sink.Events);

        var secondStatus = ingress.ConsumeSingleFrame(source.AsSpan(firstConsumed), out var secondConsumed);

        Assert.AreEqual(OperationStatus.Done, secondStatus);
        Assert.AreEqual(secondFrame.Length, secondConsumed);
        CollectionAssert.AreEqual(TwoMessageEvents, sink.Events);
        CollectionAssert.AreEqual(secondPayload, sink.Payload.ToArray());
    }

    [TestMethod]
    public void SingleFrameConsumeLeavesFollowingFrameAfterExtendedPayloadUntouched()
    {
        byte[] payload = [10, 20, 30, 40, 50];
        var extendedFrame = EncodeInboundExtended("tx"u8, payload);
        var followingFrame = EncodeBasic("verack"u8, [], corruptChecksum: false);
        var source = extendedFrame.Concat(followingFrame).ToArray();
        var sink = new RecordingSink();
        using var ingress = CreateIngress(sink);

        Assert.AreEqual(
            OperationStatus.Done,
            ingress.ConsumeSingleFrame(source, out var firstConsumed));

        Assert.AreEqual(extendedFrame.Length, firstConsumed);
        AssertCommittedMessage(sink, payload);
        Assert.AreEqual(MessageHeaderFormat.Extended, sink.Headers.Single().Format);

        Assert.AreEqual(
            OperationStatus.Done,
            ingress.ConsumeSingleFrame(source.AsSpan(firstConsumed), out var secondConsumed));
        Assert.AreEqual(followingFrame.Length, secondConsumed);
        Assert.AreEqual(2, sink.Headers.Count);
    }

    [TestMethod]
    public void SingleFrameChecksumFailureLeavesFollowingFrameUntouched()
    {
        byte[] payload = [1, 2, 3];
        var badFrame = EncodeBasic("tx"u8, payload, corruptChecksum: true);
        var followingFrame = EncodeBasic("verack"u8, [], corruptChecksum: false);
        var source = badFrame.Concat(followingFrame).ToArray();
        var sink = new RecordingSink();
        using var ingress = CreateIngress(sink);

        Assert.AreEqual(
            OperationStatus.InvalidData,
            ingress.ConsumeSingleFrame(source, out var bytesConsumed));

        Assert.AreEqual(badFrame.Length, bytesConsumed);
        Assert.IsTrue(ingress.IsFaulted);
        CollectionAssert.AreEqual(WrongChecksumEvents, sink.Events);
        CollectionAssert.AreEqual(payload, sink.Payload.ToArray());
    }

    [TestMethod]
    public void SingleFrameConsumeCompletesAtEveryHeaderSplit()
    {
        byte[] payload = [1, 2, 3, 4];
        var frame = EncodeBasic("ping"u8, payload, corruptChecksum: false);
        var followingFrame = EncodeBasic("verack"u8, [], corruptChecksum: false);
        var remainder = frame.Concat(followingFrame).ToArray();

        for (var split = 0; split <= MessageHeaderCodec.BasicHeaderLength; split++)
        {
            var sink = new RecordingSink();
            var policy = new RecordingAdmissionPolicy(isAdmitted: true);
            using var ingress = new MessageIngressStateMachine(
                NetworkMagic,
                MaximumPayloadLength,
                sink,
                policy);

            Assert.AreEqual(
                OperationStatus.NeedMoreData,
                ingress.ConsumeSingleFrame(frame.AsSpan(0, split), out var firstConsumed),
                $"First chunk at split {split}");
            Assert.AreEqual(split, firstConsumed, $"First chunk at split {split}");

            var secondSource = remainder.AsSpan(split);
            Assert.AreEqual(
                OperationStatus.Done,
                ingress.ConsumeSingleFrame(secondSource, out var secondConsumed),
                $"Second chunk at split {split}");
            Assert.AreEqual(frame.Length - split, secondConsumed, $"Second chunk at split {split}");
            Assert.AreEqual(1, policy.Calls, $"Policy calls at split {split}");
            AssertCommittedMessage(sink, payload);
        }
    }

    [TestMethod]
    public void AdmissionPolicyRunsOncePerFrameInMultiFrameConsume()
    {
        var firstFrame = EncodeBasic("verack"u8, [], corruptChecksum: false);
        var secondFrame = EncodeBasic("ping"u8, [1, 2, 3, 4], corruptChecksum: false);
        var source = firstFrame.Concat(secondFrame).ToArray();
        var sink = new RecordingSink();
        var policy = new RecordingAdmissionPolicy(isAdmitted: true);
        using var ingress = new MessageIngressStateMachine(
            NetworkMagic,
            MaximumPayloadLength,
            sink,
            policy);

        Assert.AreEqual(OperationStatus.Done, ingress.Consume(source, out var bytesConsumed));

        Assert.AreEqual(source.Length, bytesConsumed);
        Assert.AreEqual(2, policy.Calls);
        CollectionAssert.AreEqual(TwoMessageEvents, sink.Events);
    }

    [TestMethod]
    public void AdmissionRejectionStopsAtHugeBasicHeaderBoundary()
    {
        var header = EncodeInboundBasicHeader("block"u8, uint.MaxValue);

        AssertRejectedAtEveryHeaderSplit(header);
    }

    [TestMethod]
    public void AdmissionRejectionStopsAtHugeExtendedHeaderBoundary()
    {
        var header = EncodeInboundExtendedHeader("block"u8, ulong.MaxValue);

        AssertRejectedAtEveryHeaderSplit(header);
    }

    [TestMethod]
    public void AdmissionPolicyExceptionFaultsWithoutStartingOrReplayingFrame()
    {
        var frame = EncodeBasic("verack"u8, [], corruptChecksum: false);
        var sink = new RecordingSink();
        var policy = new ThrowingAdmissionPolicy();
        using var ingress = new MessageIngressStateMachine(
            NetworkMagic,
            MaximumPayloadLength,
            sink,
            policy);

        var bytesConsumed = -1;
        Assert.ThrowsException<ExpectedPolicyException>(() => ingress.Consume(frame, out bytesConsumed));
        Assert.AreEqual(MessageHeaderCodec.BasicHeaderLength, bytesConsumed);
        Assert.IsTrue(ingress.IsFaulted);
        Assert.AreEqual(1, policy.Calls);
        Assert.AreEqual(0, sink.Events.Count);

        Assert.AreEqual(OperationStatus.InvalidData, ingress.Consume(frame, out var retryConsumed));
        Assert.AreEqual(0, retryConsumed);
        Assert.AreEqual(1, policy.Calls);
    }

    [TestMethod]
    public void ReentrantAdmissionPolicyFaultsWithoutStartingFrame()
    {
        var frame = EncodeBasic("verack"u8, [], corruptChecksum: false);
        var sink = new RecordingSink();
        var policy = new ReentrantAdmissionPolicy();
        using var ingress = new MessageIngressStateMachine(
            NetworkMagic,
            MaximumPayloadLength,
            sink,
            policy);
        policy.Ingress = ingress;

        Assert.ThrowsException<InvalidOperationException>(() => ingress.Consume(frame, out _));
        Assert.IsTrue(ingress.IsFaulted);
        Assert.AreEqual(1, policy.Calls);
        Assert.AreEqual(0, sink.Events.Count);

        Assert.AreEqual(OperationStatus.InvalidData, ingress.Consume(frame, out var retryConsumed));
        Assert.AreEqual(0, retryConsumed);
        Assert.AreEqual(1, policy.Calls);
    }

    [TestMethod]
    public void AdmissionPolicyCannotHideAReentryAttempt()
    {
        var frame = EncodeBasic("verack"u8, [], corruptChecksum: false);
        var sink = new RecordingSink();
        var policy = new CatchingReentrantAdmissionPolicy();
        using var ingress = new MessageIngressStateMachine(
            NetworkMagic,
            MaximumPayloadLength,
            sink,
            policy);
        policy.Ingress = ingress;

        Assert.AreEqual(OperationStatus.InvalidData, ingress.Consume(frame, out var bytesConsumed));

        Assert.AreEqual(MessageHeaderCodec.BasicHeaderLength, bytesConsumed);
        Assert.IsTrue(ingress.IsFaulted);
        Assert.AreEqual(1, policy.Calls);
        Assert.AreEqual(0, sink.Events.Count);
    }

    [TestMethod]
    public void InboundSmallExtendedFrameStreamsWithoutBasicChecksum()
    {
        byte[] payload = [10, 20, 30, 40, 50];
        var frame = EncodeInboundExtended("tx"u8, payload);
        var sink = new RecordingSink();
        using var ingress = CreateIngress(sink);

        for (var index = 0; index < frame.Length; index++)
        {
            var status = ingress.Consume(frame.AsSpan(index, 1), out var bytesConsumed);

            Assert.AreEqual(1, bytesConsumed, $"Byte {index}");
            Assert.AreEqual(
                index == frame.Length - 1 ? OperationStatus.Done : OperationStatus.NeedMoreData,
                status,
                $"Byte {index}");
        }

        AssertCommittedMessage(sink, payload);
        Assert.AreEqual(MessageHeaderFormat.Extended, sink.Headers.Single().Format);
    }

    [TestMethod]
    public void MaximumExtendedLengthConsumesTinyPrefixWithoutNarrowingOrPreallocation()
    {
        byte[] prefixPayload = [1, 2, 3];
        var header = EncodeInboundExtendedHeader("block"u8, ulong.MaxValue);
        var source = header.Concat(prefixPayload).ToArray();
        var sink = new RecordingSink();
        using var ingress = new MessageIngressStateMachine(NetworkMagic, ulong.MaxValue, sink);

        var status = ingress.Consume(source, out var bytesConsumed);

        Assert.AreEqual(OperationStatus.NeedMoreData, status);
        Assert.AreEqual(source.Length, bytesConsumed);
        Assert.AreEqual(ulong.MaxValue, sink.Headers.Single().PayloadLength);
        CollectionAssert.AreEqual(prefixPayload, sink.Payload.ToArray());

        Assert.AreEqual(OperationStatus.InvalidData, ingress.CompleteEndOfInput());
        CollectionAssert.AreEqual(HugeExtendedPrefixEvents, sink.Events);
    }

    [TestMethod]
    public void RepeatedExtendedChunksAllocateNothingAfterWarmUp()
    {
        const int measuredIterations = 256;
        var header = EncodeInboundExtendedHeader("block"u8, ulong.MaxValue);
        var chunk = new byte[16 * 1024];
        var sink = new CountingSink();
        using var ingress = new MessageIngressStateMachine(NetworkMagic, ulong.MaxValue, sink);

        Assert.AreEqual(OperationStatus.NeedMoreData, ingress.Consume(header, out var headerBytesConsumed));
        Assert.AreEqual(header.Length, headerBytesConsumed);
        Assert.AreEqual(OperationStatus.NeedMoreData, ingress.Consume(chunk, out var warmUpBytesConsumed));
        Assert.AreEqual(chunk.Length, warmUpBytesConsumed);

        var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        var statusesAreValid = true;
        var consumedLengthsAreValid = true;
        for (var iteration = 0; iteration < measuredIterations; iteration++)
        {
            var status = ingress.Consume(chunk, out var bytesConsumed);
            statusesAreValid &= status == OperationStatus.NeedMoreData;
            consumedLengthsAreValid &= bytesConsumed == chunk.Length;
        }

        var allocatedAfter = GC.GetAllocatedBytesForCurrentThread();

        Assert.IsTrue(statusesAreValid);
        Assert.IsTrue(consumedLengthsAreValid);
        Assert.AreEqual(allocatedBefore, allocatedAfter);
        Assert.AreEqual(1, sink.StartCalls);
        Assert.AreEqual(measuredIterations + 1, sink.PayloadCalls);
        Assert.AreEqual(
            (ulong)(measuredIterations + 1) * (ulong)chunk.Length,
            sink.PayloadBytes);
        Assert.AreEqual(OperationStatus.InvalidData, ingress.CompleteEndOfInput());
        Assert.AreEqual(1, sink.AbortCalls);
    }

    [TestMethod]
    public void WrongChecksumAbortsAndLeavesFollowingFrameUntouched()
    {
        byte[] badPayload = [1, 2, 3];
        var badFrame = EncodeBasic("tx"u8, badPayload, corruptChecksum: true);
        var followingFrame = EncodeBasic("verack"u8, [], corruptChecksum: false);
        var source = badFrame.Concat(followingFrame).ToArray();
        var sink = new RecordingSink();
        using var ingress = CreateIngress(sink);

        var status = ingress.Consume(source, out var bytesConsumed);

        Assert.AreEqual(OperationStatus.InvalidData, status);
        Assert.AreEqual(badFrame.Length, bytesConsumed);
        Assert.IsTrue(ingress.IsFaulted);
        CollectionAssert.AreEqual(WrongChecksumEvents, sink.Events);
        CollectionAssert.AreEqual(badPayload, sink.Payload.ToArray());

        Assert.AreEqual(
            OperationStatus.InvalidData,
            ingress.Consume(source.AsSpan(bytesConsumed), out var retryConsumed));
        Assert.AreEqual(0, retryConsumed);
        Assert.AreEqual(3, sink.Events.Count);
    }

    [TestMethod]
    public void MalformedHeaderFaultsAtHeaderBoundaryWithoutResynchronizing()
    {
        var frame = EncodeBasic("tx"u8, Payload, corruptChecksum: false);
        frame[0] ^= 0xff;
        var sink = new RecordingSink();
        using var ingress = CreateIngress(sink);

        var status = ingress.Consume(frame, out var bytesConsumed);

        Assert.AreEqual(OperationStatus.InvalidData, status);
        Assert.AreEqual(MessageHeaderCodec.BasicHeaderLength, bytesConsumed);
        Assert.IsTrue(ingress.IsFaulted);
        Assert.AreEqual(0, sink.Events.Count);

        Assert.AreEqual(
            OperationStatus.InvalidData,
            ingress.Consume(frame.AsSpan(bytesConsumed), out var retryConsumed));
        Assert.AreEqual(0, retryConsumed);
    }

    [TestMethod]
    public void PayloadCallbackExceptionFaultsWithoutReplayingTheChunk()
    {
        var frame = EncodeBasic("tx"u8, Payload, corruptChecksum: false);
        var sink = new ThrowingPayloadSink();
        using var ingress = CreateIngress(sink);

        Assert.ThrowsException<ExpectedSinkException>(() => ingress.Consume(frame, out _));
        Assert.IsTrue(ingress.IsFaulted);
        Assert.AreEqual(1, sink.PayloadCalls);

        Assert.AreEqual(
            OperationStatus.InvalidData,
            ingress.Consume(frame, out var retryConsumed));
        Assert.AreEqual(0, retryConsumed);
        Assert.AreEqual(1, sink.PayloadCalls);
    }

    [TestMethod]
    public void ReentrantCallbackFaultsTheOuterConsume()
    {
        var frame = EncodeBasic("verack"u8, [], corruptChecksum: false);
        var sink = new ReentrantSink();
        using var ingress = CreateIngress(sink);
        sink.Ingress = ingress;

        Assert.ThrowsException<InvalidOperationException>(() => ingress.Consume(frame, out _));
        Assert.IsTrue(ingress.IsFaulted);
        Assert.AreEqual(1, sink.StartCalls);
    }

    [TestMethod]
    public void SinkCanCatchRejectedReentryWithoutPoisoningOuterConsume()
    {
        var frame = EncodeBasic("verack"u8, [], corruptChecksum: false);
        var sink = new CatchingReentrantSink();
        using var ingress = CreateIngress(sink);
        sink.Ingress = ingress;

        Assert.AreEqual(OperationStatus.Done, ingress.Consume(frame, out var bytesConsumed));

        Assert.AreEqual(frame.Length, bytesConsumed);
        Assert.IsFalse(ingress.IsFaulted);
        Assert.AreEqual(1, sink.StartCalls);
        Assert.AreEqual(1, sink.CompletionCalls);
    }

    [TestMethod]
    public void TruncatedPayloadIsAbortedExplicitlyAtEndOfInput()
    {
        var frame = EncodeBasic("tx"u8, Payload, corruptChecksum: false);
        var prefixLength = MessageHeaderCodec.BasicHeaderLength + 5;
        var sink = new RecordingSink();
        using var ingress = CreateIngress(sink);

        Assert.AreEqual(
            OperationStatus.NeedMoreData,
            ingress.Consume(frame.AsSpan(0, prefixLength), out var bytesConsumed));
        Assert.AreEqual(prefixLength, bytesConsumed);

        Assert.AreEqual(OperationStatus.InvalidData, ingress.CompleteEndOfInput());
        Assert.IsTrue(ingress.IsCompleted);
        Assert.IsTrue(ingress.IsFaulted);
        CollectionAssert.AreEqual(TruncatedPayloadEvents, sink.Events);
    }

    [TestMethod]
    public void TruncatedHeaderEndsWithoutInventingAMessage()
    {
        var frame = EncodeBasic("tx"u8, Payload, corruptChecksum: false);
        var sink = new RecordingSink();
        using var ingress = CreateIngress(sink);

        Assert.AreEqual(
            OperationStatus.NeedMoreData,
            ingress.Consume(frame.AsSpan(0, 10), out var bytesConsumed));
        Assert.AreEqual(10, bytesConsumed);

        Assert.AreEqual(OperationStatus.InvalidData, ingress.CompleteEndOfInput());
        Assert.IsTrue(ingress.IsFaulted);
        Assert.AreEqual(0, sink.Events.Count);
    }

    [TestMethod]
    public void CleanEndOfInputIsIdempotentAndRejectsFurtherData()
    {
        var frame = EncodeBasic("verack"u8, [], corruptChecksum: false);
        var sink = new RecordingSink();
        using var ingress = CreateIngress(sink);

        Assert.AreEqual(OperationStatus.Done, ingress.Consume(frame, out _));
        Assert.AreEqual(OperationStatus.Done, ingress.CompleteEndOfInput());
        Assert.AreEqual(OperationStatus.Done, ingress.CompleteEndOfInput());
        Assert.IsTrue(ingress.IsCompleted);
        Assert.IsFalse(ingress.IsFaulted);
        Assert.ThrowsException<InvalidOperationException>(() => ingress.Consume([], out _));
    }

    [TestMethod]
    public void DisposeFromCallbackFaultsInsteadOfInvalidatingOuterState()
    {
        var frame = EncodeBasic("verack"u8, [], corruptChecksum: false);
        var sink = new DisposingSink();
        using var ingress = CreateIngress(sink);
        sink.Ingress = ingress;

        Assert.ThrowsException<InvalidOperationException>(() => ingress.Consume(frame, out _));
        Assert.IsTrue(ingress.IsFaulted);
        Assert.AreEqual(1, sink.StartCalls);
    }

    [TestMethod]
    public void ConstructorRejectsInvalidNetworkMagicLength()
    {
        var sink = new RecordingSink();
        Assert.ThrowsException<ArgumentException>(() => new MessageIngressStateMachine([], 0, sink));
        Assert.ThrowsException<ArgumentException>(() => new MessageIngressStateMachine([1, 2, 3], 0, sink));
        Assert.ThrowsException<ArgumentException>(() => new MessageIngressStateMachine([1, 2, 3, 4, 5], 0, sink));
    }

    private static MessageIngressStateMachine CreateIngress(IMessageIngressSink sink) =>
        new(NetworkMagic, MaximumPayloadLength, sink);

    private static byte[] EncodeBasic(
        ReadOnlySpan<byte> command,
        byte[] payload,
        bool corruptChecksum)
    {
        var checksum = MessageChecksum.Compute(payload);
        var checksumBytes = new byte[MessageChecksum.Length];
        Assert.AreEqual(
            OperationStatus.Done,
            checksum.TryCopyTo(checksumBytes, out var checksumBytesWritten));
        Assert.AreEqual(MessageChecksum.Length, checksumBytesWritten);
        if (corruptChecksum)
        {
            checksumBytes[0] ^= 0xff;
        }

        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic(
                command,
                (uint)payload.Length,
                checksumBytes,
                out var header));
        var frame = new byte[MessageHeaderCodec.BasicHeaderLength + payload.Length];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(
                frame,
                NetworkMagic,
                header,
                MaximumPayloadLength,
                out var headerBytesWritten));
        Assert.AreEqual(MessageHeaderCodec.BasicHeaderLength, headerBytesWritten);
        payload.CopyTo(frame, headerBytesWritten);
        return frame;
    }

    private static byte[] EncodeInboundExtended(ReadOnlySpan<byte> command, byte[] payload)
    {
        var header = EncodeInboundExtendedHeader(command, (ulong)payload.Length);
        var frame = new byte[header.Length + payload.Length];
        header.CopyTo(frame, 0);
        payload.CopyTo(frame, MessageHeaderCodec.ExtendedHeaderLength);
        return frame;
    }

    private static byte[] EncodeInboundBasicHeader(ReadOnlySpan<byte> command, uint payloadLength)
    {
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic(
                command,
                payloadLength,
                new byte[MessageChecksum.Length],
                out var header));
        var encoded = new byte[MessageHeaderCodec.BasicHeaderLength];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(
                encoded,
                NetworkMagic,
                header,
                ulong.MaxValue,
                out var bytesWritten));
        Assert.AreEqual(encoded.Length, bytesWritten);
        return encoded;
    }

    private static byte[] EncodeInboundExtendedHeader(ReadOnlySpan<byte> command, ulong payloadLength)
    {
        var header = new byte[MessageHeaderCodec.ExtendedHeaderLength];
        NetworkMagic.CopyTo(header, 0);
        MessageHeaderCodec.ExtendedCommand.CopyTo(header.AsSpan(4));
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(16), uint.MaxValue);
        command.CopyTo(header.AsSpan(24));
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(36), payloadLength);
        return header;
    }

    private static void AssertRejectedAtEveryHeaderSplit(byte[] header)
    {
        byte[] payloadPrefix = [1, 2, 3];
        var source = header.Concat(payloadPrefix).ToArray();

        for (var split = 0; split <= header.Length; split++)
        {
            var sink = new RecordingSink();
            var policy = new RecordingAdmissionPolicy(isAdmitted: false);
            using var ingress = new MessageIngressStateMachine(
                NetworkMagic,
                ulong.MaxValue,
                sink,
                policy);

            var firstStatus = ingress.ConsumeSingleFrame(
                source.AsSpan(0, split),
                out var firstConsumed);
            Assert.AreEqual(split, firstConsumed, $"First chunk at split {split}");

            if (split < header.Length)
            {
                Assert.AreEqual(
                    OperationStatus.NeedMoreData,
                    firstStatus,
                    $"First chunk at split {split}");
                Assert.AreEqual(
                    OperationStatus.InvalidData,
                    ingress.ConsumeSingleFrame(source.AsSpan(split), out var secondConsumed),
                    $"Second chunk at split {split}");
                Assert.AreEqual(header.Length - split, secondConsumed, $"Second chunk at split {split}");
            }
            else
            {
                Assert.AreEqual(OperationStatus.InvalidData, firstStatus, $"First chunk at split {split}");
            }

            Assert.IsTrue(ingress.IsFaulted, $"Fault state at split {split}");
            Assert.AreEqual(1, policy.Calls, $"Policy calls at split {split}");
            Assert.AreEqual(0, sink.Events.Count, $"Sink events at split {split}");
        }
    }

    private static void AssertCommittedMessage(RecordingSink sink, byte[] expectedPayload)
    {
        Assert.AreEqual(1, sink.Headers.Count);
        CollectionAssert.AreEqual(expectedPayload, sink.Payload.ToArray());
        CollectionAssert.AreEqual(
            new[] { MessageIngressCompletion.FrameValidated },
            sink.Completions);
    }

    private sealed class RecordingSink : IMessageIngressSink
    {
        public List<MessageHeader> Headers { get; } = [];

        public List<byte> Payload { get; } = [];

        public List<MessageIngressCompletion> Completions { get; } = [];

        public List<string> Events { get; } = [];

        public void OnMessageStarted(in MessageHeader header)
        {
            Headers.Add(header);
            Span<byte> command = stackalloc byte[MessageCommand.MaximumLength];
            Assert.AreEqual(
                OperationStatus.Done,
                header.Command.TryCopyTo(command, out var bytesWritten));
            Events.Add($"start:{System.Text.Encoding.ASCII.GetString(command[..bytesWritten])}");
        }

        public void OnProvisionalPayload(ReadOnlySpan<byte> payload)
        {
            foreach (var value in payload)
            {
                Payload.Add(value);
            }

            Events.Add($"payload:{payload.Length}");
        }

        public void OnMessageCompleted(MessageIngressCompletion completion)
        {
            Completions.Add(completion);
            Events.Add(completion == MessageIngressCompletion.FrameValidated ? "commit" : "abort");
        }
    }

    private sealed class ThrowingPayloadSink : IMessageIngressSink
    {
        public int PayloadCalls { get; private set; }

        public void OnMessageStarted(in MessageHeader header)
        {
        }

        public void OnProvisionalPayload(ReadOnlySpan<byte> payload)
        {
            PayloadCalls++;
            throw new ExpectedSinkException();
        }

        public void OnMessageCompleted(MessageIngressCompletion completion)
        {
            Assert.Fail("Completion must not be delivered after a payload callback exception.");
        }
    }

    private sealed class ReentrantSink : IMessageIngressSink
    {
        public MessageIngressStateMachine? Ingress { get; set; }

        public int StartCalls { get; private set; }

        public void OnMessageStarted(in MessageHeader header)
        {
            StartCalls++;
            Ingress!.Consume([], out _);
        }

        public void OnProvisionalPayload(ReadOnlySpan<byte> payload)
        {
        }

        public void OnMessageCompleted(MessageIngressCompletion completion)
        {
        }
    }

    private sealed class DisposingSink : IMessageIngressSink
    {
        public MessageIngressStateMachine? Ingress { get; set; }

        public int StartCalls { get; private set; }

        public void OnMessageStarted(in MessageHeader header)
        {
            StartCalls++;
            Ingress!.Dispose();
        }

        public void OnProvisionalPayload(ReadOnlySpan<byte> payload)
        {
        }

        public void OnMessageCompleted(MessageIngressCompletion completion)
        {
        }
    }

    private sealed class CatchingReentrantSink : IMessageIngressSink
    {
        public MessageIngressStateMachine? Ingress { get; set; }

        public int StartCalls { get; private set; }

        public int CompletionCalls { get; private set; }

        public void OnMessageStarted(in MessageHeader header)
        {
            StartCalls++;
            try
            {
                Ingress!.Consume([], out _);
            }
            catch (InvalidOperationException)
            {
            }
        }

        public void OnProvisionalPayload(ReadOnlySpan<byte> payload)
        {
        }

        public void OnMessageCompleted(MessageIngressCompletion completion)
        {
            CompletionCalls++;
        }
    }

    private sealed class CountingSink : IMessageIngressSink
    {
        public int StartCalls { get; private set; }

        public int PayloadCalls { get; private set; }

        public ulong PayloadBytes { get; private set; }

        public int AbortCalls { get; private set; }

        public void OnMessageStarted(in MessageHeader header)
        {
            StartCalls++;
        }

        public void OnProvisionalPayload(ReadOnlySpan<byte> payload)
        {
            PayloadCalls++;
            PayloadBytes += (ulong)payload.Length;
        }

        public void OnMessageCompleted(MessageIngressCompletion completion)
        {
            if (completion == MessageIngressCompletion.FrameAborted)
            {
                AbortCalls++;
            }
        }
    }

    private sealed class RecordingAdmissionPolicy(bool isAdmitted) : IMessageIngressAdmissionPolicy
    {
        public int Calls { get; private set; }

        public bool IsAdmitted(in MessageHeader header)
        {
            Calls++;
            return isAdmitted;
        }
    }

    private sealed class ThrowingAdmissionPolicy : IMessageIngressAdmissionPolicy
    {
        public int Calls { get; private set; }

        public bool IsAdmitted(in MessageHeader header)
        {
            Calls++;
            throw new ExpectedPolicyException();
        }
    }

    private sealed class ReentrantAdmissionPolicy : IMessageIngressAdmissionPolicy
    {
        public MessageIngressStateMachine? Ingress { get; set; }

        public int Calls { get; private set; }

        public bool IsAdmitted(in MessageHeader header)
        {
            Calls++;
            Ingress!.ConsumeSingleFrame([], out _);
            return true;
        }
    }

    private sealed class CatchingReentrantAdmissionPolicy : IMessageIngressAdmissionPolicy
    {
        public MessageIngressStateMachine? Ingress { get; set; }

        public int Calls { get; private set; }

        public bool IsAdmitted(in MessageHeader header)
        {
            Calls++;
            try
            {
                Ingress!.ConsumeSingleFrame([], out _);
            }
            catch (InvalidOperationException)
            {
            }

            return true;
        }
    }

    private sealed class ExpectedSinkException : Exception;

    private sealed class ExpectedPolicyException : Exception;
}
