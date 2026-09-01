using System.Buffers;
using System.Buffers.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Messages;
using Staffetta.Core.Protocol.Relay;
using Staffetta.Core.Protocol.Sessions;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Tests.Protocol.Sessions;

[TestClass]
public sealed class BsvPeerSessionIngressAdapterStressTests
{
    private const int MinimumProtocolVersion = VersionPayloadCodec.CurrentProtocolVersion;
    private const ulong LocalNonce = 0x0102_0304_0506_0708;
    private const ulong PeerNonce = 0x1112_1314_1516_1718;
    private const ulong MaximumPayloadLength = 16 * 1024 * 1024;
    private const long AllocationSlopeTolerance = 512;

    private static readonly byte[] NetworkMagic = [0xe3, 0xe1, 0xf3, 0xe8];

    [TestMethod]
    public void MaximumInventoryIsAcceptedAcrossChunkingWithoutCountBasedAllocation()
    {
        var observedTransactionId = Hash256.DoubleSha256("last-vector"u8);
        var absentTransactionId = Hash256.DoubleSha256("absent-vector"u8);
        var firstTransactionId = Hash256.DoubleSha256("first-vector"u8);
        var maximumPayload = CreateInventoryPayload(
            checked((int)BsvPeerSessionIngressAdapter.MaximumInventoryCount),
            observedTransactionId);
        var maximumFrame = EncodeBasic("inv"u8, maximumPayload);

        using (var oneShot = CreateReadySession(new ExactTransactionSink()))
        {
            PrepareBroadcast(oneShot, observedTransactionId);
            ConsumeWholeFrame(oneShot, maximumFrame);
            Assert.IsTrue(oneShot.WasObservedFromPeer);
        }

        using (var chunked = CreateReadySession(new ExactTransactionSink()))
        {
            PrepareBroadcast(chunked, observedTransactionId);
            ConsumeInFixedChunks(chunked, maximumFrame, chunkLength: 25);
            Assert.IsTrue(chunked.WasObservedFromPeer);
        }

        var smallFrame = EncodeBasic("inv"u8, CreateInventoryPayload(1, firstTransactionId));
        using var measured = CreateReadySession(new ExactTransactionSink());
        PrepareBroadcast(measured, absentTransactionId);
        ConsumeWholeFrame(measured, smallFrame);

        var smallAllocated = MeasureWholeFrameAllocation(measured, smallFrame);
        var maximumAllocated = MeasureWholeFrameAllocation(measured, maximumFrame);

        Assert.IsFalse(measured.WasObservedFromPeer);
        Assert.IsTrue(
            maximumAllocated <= smallAllocated + AllocationSlopeTolerance,
            $"One-vector inv allocated {smallAllocated} bytes; 50,000-vector inv allocated " +
            $"{maximumAllocated} bytes. The {AllocationSlopeTolerance}-byte tolerance covers " +
            "constant framing/hash-validator noise, not count-proportional storage.");
    }

    [TestMethod]
    public void InventoryAboveTheMaximumIsRejectedAtTheHeaderBoundary()
    {
        using var session = CreateReadySession(new ExactTransactionSink());
        var oversizedCount = BsvPeerSessionIngressAdapter.MaximumInventoryCount + 1;
        var oversizedPayloadLength = checked(3UL + (oversizedCount * InventoryVectorCodec.EncodedLength));
        var header = EncodeBasicHeader("inv"u8, checked((uint)oversizedPayloadLength));
        var headerAndUnacceptedPayloadByte = new byte[header.Length + 1];
        header.CopyTo(headerAndUnacceptedPayloadByte, 0);
        headerAndUnacceptedPayloadByte[^1] = 0xfd;

        Assert.AreEqual(
            OperationStatus.InvalidData,
            session.Consume(headerAndUnacceptedPayloadByte, out var consumed));
        Assert.AreEqual(header.Length, consumed);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            session.Consume(headerAndUnacceptedPayloadByte.AsSpan(consumed), out consumed));
        Assert.AreEqual(0, consumed);
    }

    [TestMethod]
    public void MultiMegabyteScriptStreamsWithExactSummaryAndLengthIndependentAllocation()
    {
        const int scriptLength = 4 * 1024 * 1024;
        var smallTransaction = CreateSingleInputScriptTransaction(1);
        var largeTransaction = CreateSingleInputScriptTransaction(scriptLength);
        var smallFrame = EncodeBasic("tx"u8, smallTransaction);
        var largeFrame = EncodeBasic("tx"u8, largeTransaction);
        var expectedTransactionId = Hash256.DoubleSha256(largeTransaction);
        var sink = new ExactTransactionSink();
        using var session = CreateReadySession(sink);
        ConsumeWholeFrame(session, smallFrame);

        var smallAllocated = MeasureChunkedFrameAllocation(session, smallFrame, chunkLength: 16 * 1024);
        var largeAllocated = MeasureChunkedFrameAllocation(session, largeFrame, chunkLength: 16 * 1024);

        Assert.AreEqual(3, sink.CommittedCount);
        Assert.AreEqual(1UL, sink.LastSummary.InputCount);
        Assert.AreEqual(1UL, sink.LastSummary.OutputCount);
        Assert.AreEqual((ulong)scriptLength, sink.LastSummary.TotalInputScriptLength);
        Assert.AreEqual((ulong)largeTransaction.Length, sink.LastSummary.SerializedLength);
        Assert.AreEqual(expectedTransactionId, sink.LastSummary.TransactionId);
        Assert.AreEqual((ulong)scriptLength, sink.LastCommittedInputScriptBytes);
        Assert.AreEqual(0UL, sink.LastCommittedOutputScriptBytes);
        Assert.IsTrue(
            largeAllocated <= smallAllocated + AllocationSlopeTolerance,
            $"One-byte script frame allocated {smallAllocated} bytes; four-megabyte script frame " +
            $"allocated {largeAllocated} bytes. The {AllocationSlopeTolerance}-byte tolerance " +
            "allows constant framing/hash-validator noise only.");
    }

    [TestMethod]
    public void HighOutputCountHasExactCallbacksWithoutEventAllocationSlope()
    {
        const int highOutputCount = 10_000;
        var oneOutputTransaction = CreateHighOutputCountTransaction(1);
        var highOutputTransaction = CreateHighOutputCountTransaction(highOutputCount);
        var oneOutputFrame = EncodeBasic("tx"u8, oneOutputTransaction);
        var highOutputFrame = EncodeBasic("tx"u8, highOutputTransaction);
        var sink = new ExactTransactionSink();
        using var session = CreateReadySession(sink);
        ConsumeWholeFrame(session, oneOutputFrame);

        var oneOutputAllocated = MeasureWholeFrameAllocation(session, oneOutputFrame);
        var highOutputAllocated = MeasureWholeFrameAllocation(session, highOutputFrame);

        Assert.AreEqual((ulong)highOutputCount, sink.LastSummary.OutputCount);
        Assert.AreEqual((ulong)highOutputCount, sink.LastCommittedDeclaredOutputCount);
        Assert.AreEqual((ulong)highOutputCount, sink.LastCommittedOutputStartedCount);
        Assert.AreEqual((ulong)highOutputCount, sink.LastCommittedOutputCompletedCount);
        Assert.AreEqual(Hash256.DoubleSha256(highOutputTransaction), sink.LastSummary.TransactionId);
        Assert.IsTrue(
            highOutputAllocated <= oneOutputAllocated + AllocationSlopeTolerance,
            $"One-output frame allocated {oneOutputAllocated} bytes; {highOutputCount}-output " +
            $"frame allocated {highOutputAllocated} bytes. The {AllocationSlopeTolerance}-byte " +
            "tolerance excludes event-wise allocation growth.");
    }

    [TestMethod]
    public void BytewiseCompactSizesMakeProgressWithoutCallbackReplay()
    {
        const int inputCount = 253;
        const int outputCount = 253;
        const int firstInputScriptLength = 253;
        var transaction = CreateBoundaryTransaction(inputCount, outputCount, firstInputScriptLength);
        var frame = EncodeBasic("tx"u8, transaction);
        var sink = new ExactTransactionSink();
        using var session = CreateReadySession(sink);

        ConsumeInFixedChunks(session, frame, chunkLength: 1);

        Assert.AreEqual(1, sink.CommittedCount);
        Assert.AreEqual((ulong)inputCount, sink.LastSummary.InputCount);
        Assert.AreEqual((ulong)outputCount, sink.LastSummary.OutputCount);
        Assert.AreEqual((ulong)inputCount, sink.LastCommittedDeclaredInputCount);
        Assert.AreEqual((ulong)outputCount, sink.LastCommittedDeclaredOutputCount);
        Assert.AreEqual((ulong)inputCount, sink.LastCommittedInputStartedCount);
        Assert.AreEqual((ulong)inputCount, sink.LastCommittedInputCompletedCount);
        Assert.AreEqual((ulong)outputCount, sink.LastCommittedOutputStartedCount);
        Assert.AreEqual((ulong)outputCount, sink.LastCommittedOutputCompletedCount);
        Assert.AreEqual((ulong)firstInputScriptLength, sink.LastCommittedInputScriptBytes);
        Assert.AreEqual(Hash256.DoubleSha256(transaction), sink.LastSummary.TransactionId);
    }

    private static BsvPeerSessionIngressAdapter CreateReadySession(ILegacyTransactionSink sink)
    {
        var session = new BsvPeerSessionIngressAdapter(
            NetworkMagic,
            MaximumPayloadLength,
            MinimumProtocolVersion,
            sink);
        Assert.AreEqual(OperationStatus.Done, session.StartHandshake(LocalNonce));
        Span<BsvHandshakeOutput> outputs = stackalloc BsvHandshakeOutput[3];
        Assert.AreEqual(OperationStatus.Done, session.DrainHandshakeOutputs(outputs, out var written));
        Assert.AreEqual(1, written);

        ConsumeWholeFrame(session, EncodeBasic("version"u8, CreateVersionPayload()));
        Assert.AreEqual(OperationStatus.Done, session.DrainHandshakeOutputs(outputs, out written));
        Assert.AreEqual(2, written);

        ConsumeWholeFrame(session, EncodeBasic("verack"u8, []));
        Assert.AreEqual(OperationStatus.Done, session.DrainHandshakeOutputs(outputs, out written));
        Assert.AreEqual(1, written);
        Assert.AreEqual(BsvHandshakeState.Ready, session.HandshakeState);
        return session;
    }

    private static void PrepareBroadcast(
        BsvPeerSessionIngressAdapter session,
        Hash256 transactionId)
    {
        Span<BsvTransactionBroadcastOutput> outputs =
            stackalloc BsvTransactionBroadcastOutput[BsvTransactionBroadcastStateMachine.MaximumOutputCount];
        Assert.AreEqual(OperationStatus.Done, session.StartBroadcast(transactionId));
        Assert.AreEqual(OperationStatus.Done, session.DrainBroadcastOutputs(outputs, out var written));
        Assert.AreEqual(1, written);
        Assert.AreEqual(OperationStatus.Done, CommitInventoryEgress(session, transactionId));
        Assert.AreEqual(OperationStatus.Done, session.DrainBroadcastOutputs(outputs, out written));
        Assert.AreEqual(1, written);
    }

    private static long MeasureWholeFrameAllocation(
        BsvPeerSessionIngressAdapter session,
        ReadOnlySpan<byte> frame)
    {
        var before = GC.GetAllocatedBytesForCurrentThread();
        ConsumeWholeFrameWithoutAssertions(session, frame);
        return GC.GetAllocatedBytesForCurrentThread() - before;
    }

    private static long MeasureChunkedFrameAllocation(
        BsvPeerSessionIngressAdapter session,
        ReadOnlySpan<byte> frame,
        int chunkLength)
    {
        var before = GC.GetAllocatedBytesForCurrentThread();
        ConsumeInFixedChunksWithoutAssertions(session, frame, chunkLength);
        return GC.GetAllocatedBytesForCurrentThread() - before;
    }

    private static void ConsumeWholeFrame(
        BsvPeerSessionIngressAdapter session,
        ReadOnlySpan<byte> frame)
    {
        Assert.AreEqual(OperationStatus.Done, session.Consume(frame, out var consumed));
        Assert.AreEqual(frame.Length, consumed);
    }

    private static void ConsumeWholeFrameWithoutAssertions(
        BsvPeerSessionIngressAdapter session,
        ReadOnlySpan<byte> frame)
    {
        var status = session.Consume(frame, out var consumed);
        if (status != OperationStatus.Done || consumed != frame.Length)
        {
            throw new InvalidOperationException(
                $"Expected one complete frame, got {status} after {consumed}/{frame.Length} bytes.");
        }
    }

    private static void ConsumeInFixedChunks(
        BsvPeerSessionIngressAdapter session,
        ReadOnlySpan<byte> frame,
        int chunkLength)
    {
        var consumed = ConsumeInFixedChunksWithoutAssertions(session, frame, chunkLength);
        Assert.AreEqual(frame.Length, consumed);
    }

    private static int ConsumeInFixedChunksWithoutAssertions(
        BsvPeerSessionIngressAdapter session,
        ReadOnlySpan<byte> frame,
        int chunkLength)
    {
        var offset = 0;
        while (offset < frame.Length)
        {
            var length = Math.Min(chunkLength, frame.Length - offset);
            var status = session.Consume(frame.Slice(offset, length), out var consumed);
            if (consumed <= 0 || consumed > length)
            {
                throw new InvalidOperationException(
                    $"Ingress made invalid progress {consumed} for a {length}-byte chunk at {offset}.");
            }

            offset += consumed;
            var expectedStatus = offset == frame.Length
                ? OperationStatus.Done
                : OperationStatus.NeedMoreData;
            if (status != expectedStatus)
            {
                throw new InvalidOperationException(
                    $"Expected {expectedStatus} at {offset}/{frame.Length}, got {status}.");
            }
        }

        return offset;
    }

    private static byte[] CreateInventoryPayload(int count, Hash256 lastTransactionId)
    {
        var countLength = GetCompactSizeLength((ulong)count);
        var payload = new byte[checked(countLength + (count * InventoryVectorCodec.EncodedLength))];
        var offset = WriteCompactSize(payload, (ulong)count);
        for (var index = 0; index < count; index++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(offset), 1);
            offset += sizeof(uint);
            if (index == count - 1)
            {
                Assert.AreEqual(
                    OperationStatus.Done,
                    lastTransactionId.TryCopyWireBytesTo(payload.AsSpan(offset), out var written));
                Assert.AreEqual(Hash256.Length, written);
            }

            offset += Hash256.Length;
        }

        Assert.AreEqual(payload.Length, offset);
        return payload;
    }

    private static byte[] CreateSingleInputScriptTransaction(int scriptLength)
    {
        var scriptLengthPrefix = GetCompactSizeLength((ulong)scriptLength);
        var transaction = new byte[
            sizeof(int) + 1 + Hash256.Length + sizeof(uint) + scriptLengthPrefix + scriptLength +
            sizeof(uint) + 1 + sizeof(long) + 1 + sizeof(uint)];
        var offset = 0;
        BinaryPrimitives.WriteInt32LittleEndian(transaction.AsSpan(offset), 2);
        offset += sizeof(int);
        transaction[offset++] = 1;
        offset += Hash256.Length + sizeof(uint);
        offset += WriteCompactSize(transaction.AsSpan(offset), (ulong)scriptLength);
        transaction.AsSpan(offset, scriptLength).Fill(0x51);
        offset += scriptLength;
        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(offset), uint.MaxValue);
        offset += sizeof(uint);
        transaction[offset++] = 1;
        BinaryPrimitives.WriteInt64LittleEndian(transaction.AsSpan(offset), 1);
        offset += sizeof(long);
        transaction[offset++] = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(offset), 0);
        offset += sizeof(uint);
        Assert.AreEqual(transaction.Length, offset);
        return transaction;
    }

    private static byte[] CreateHighOutputCountTransaction(int outputCount)
    {
        var outputCountPrefix = GetCompactSizeLength((ulong)outputCount);
        var transaction = new byte[
            sizeof(int) + 1 + Hash256.Length + sizeof(uint) + 1 + sizeof(uint) +
            outputCountPrefix + (outputCount * (sizeof(long) + 1)) + sizeof(uint)];
        var offset = 0;
        BinaryPrimitives.WriteInt32LittleEndian(transaction.AsSpan(offset), 2);
        offset += sizeof(int);
        transaction[offset++] = 1;
        offset += Hash256.Length + sizeof(uint);
        transaction[offset++] = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(offset), uint.MaxValue);
        offset += sizeof(uint);
        offset += WriteCompactSize(transaction.AsSpan(offset), (ulong)outputCount);
        for (var index = 0; index < outputCount; index++)
        {
            BinaryPrimitives.WriteInt64LittleEndian(transaction.AsSpan(offset), index);
            offset += sizeof(long);
            transaction[offset++] = 0;
        }

        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(offset), 0);
        offset += sizeof(uint);
        Assert.AreEqual(transaction.Length, offset);
        return transaction;
    }

    private static byte[] CreateBoundaryTransaction(
        int inputCount,
        int outputCount,
        int firstInputScriptLength)
    {
        var inputCountPrefix = GetCompactSizeLength((ulong)inputCount);
        var outputCountPrefix = GetCompactSizeLength((ulong)outputCount);
        var firstScriptPrefix = GetCompactSizeLength((ulong)firstInputScriptLength);
        var emptyInputLength = Hash256.Length + sizeof(uint) + 1 + sizeof(uint);
        var firstInputLength =
            Hash256.Length + sizeof(uint) + firstScriptPrefix + firstInputScriptLength + sizeof(uint);
        var outputLength = sizeof(long) + 1;
        var transaction = new byte[
            sizeof(int) + inputCountPrefix + firstInputLength +
            ((inputCount - 1) * emptyInputLength) + outputCountPrefix +
            (outputCount * outputLength) + sizeof(uint)];
        var offset = 0;
        BinaryPrimitives.WriteInt32LittleEndian(transaction.AsSpan(offset), 2);
        offset += sizeof(int);
        offset += WriteCompactSize(transaction.AsSpan(offset), (ulong)inputCount);
        for (var index = 0; index < inputCount; index++)
        {
            offset += Hash256.Length;
            BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(offset), (uint)index);
            offset += sizeof(uint);
            var scriptLength = index == 0 ? firstInputScriptLength : 0;
            offset += WriteCompactSize(transaction.AsSpan(offset), (ulong)scriptLength);
            transaction.AsSpan(offset, scriptLength).Fill(0x51);
            offset += scriptLength;
            BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(offset), uint.MaxValue);
            offset += sizeof(uint);
        }

        offset += WriteCompactSize(transaction.AsSpan(offset), (ulong)outputCount);
        for (var index = 0; index < outputCount; index++)
        {
            BinaryPrimitives.WriteInt64LittleEndian(transaction.AsSpan(offset), index);
            offset += sizeof(long);
            transaction[offset++] = 0;
        }

        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(offset), 0);
        offset += sizeof(uint);
        Assert.AreEqual(transaction.Length, offset);
        return transaction;
    }

    private static int GetCompactSizeLength(ulong value) => value switch
    {
        < 0xfd => 1,
        <= ushort.MaxValue => 3,
        <= uint.MaxValue => 5,
        _ => 9,
    };

    private static int WriteCompactSize(Span<byte> destination, ulong value)
    {
        if (value < 0xfd)
        {
            destination[0] = (byte)value;
            return 1;
        }

        if (value <= ushort.MaxValue)
        {
            destination[0] = 0xfd;
            BinaryPrimitives.WriteUInt16LittleEndian(destination[1..], (ushort)value);
            return 3;
        }

        if (value <= uint.MaxValue)
        {
            destination[0] = 0xfe;
            BinaryPrimitives.WriteUInt32LittleEndian(destination[1..], (uint)value);
            return 5;
        }

        destination[0] = 0xff;
        BinaryPrimitives.WriteUInt64LittleEndian(destination[1..], value);
        return 9;
    }

    private static OperationStatus CommitInventoryEgress(
        BsvPeerSessionIngressAdapter session,
        Hash256 transactionId)
    {
        var status = session.PlanBroadcastEgress(
            new BsvTransactionBroadcastOutput(
                BsvTransactionBroadcastOutputKind.SendInventory,
                transactionId),
            out _);
        while (status == OperationStatus.Done && !session.PendingEgressSegment.IsEmpty)
        {
            var pending = session.PendingEgressSegment;
            status = session.AcknowledgeEgress(pending, pending.Length);
        }

        return status == OperationStatus.Done
            ? session.CommitEgressCompletion()
            : status;
    }

    private static byte[] CreateVersionPayload()
    {
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [192, 0, 2, 1], 8_333, out var receiving));
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [192, 0, 2, 2], 8_333, out var source));
        var version = new VersionPayload(
            MinimumProtocolVersion,
            services: 1,
            timestampUnixSeconds: 1_788_131_200,
            receiving,
            source,
            PeerNonce,
            "/Staffetta:stress/"u8,
            startHeight: 948_321,
            relay: true);
        var payload = new byte[BsvHandshakeIngressAdapter.MaximumStagedPayloadLength];
        Assert.AreEqual(OperationStatus.Done, VersionPayloadCodec.TryWrite(payload, version, out var written));
        return payload[..written];
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
            MessageHeaderCodec.TryWrite(frame, NetworkMagic, header, MaximumPayloadLength, out var headerLength));
        payload.CopyTo(frame.AsSpan(headerLength));
        return frame;
    }

    private static byte[] EncodeBasicHeader(ReadOnlySpan<byte> command, uint payloadLength)
    {
        Span<byte> checksum = stackalloc byte[MessageChecksum.Length];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic(command, payloadLength, checksum, out var header));
        var encoded = new byte[MessageHeaderCodec.BasicHeaderLength];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(encoded, NetworkMagic, header, MaximumPayloadLength, out var written));
        Assert.AreEqual(encoded.Length, written);
        return encoded;
    }

    private sealed class ExactTransactionSink : ILegacyTransactionSink
    {
        private ulong _inputStartedCount;
        private ulong _inputCompletedCount;
        private ulong _outputStartedCount;
        private ulong _outputCompletedCount;
        private ulong _inputScriptBytes;
        private ulong _outputScriptBytes;
        private ulong _declaredInputCount;
        private ulong _declaredOutputCount;

        public int CommittedCount { get; private set; }

        public LegacyTransactionSummary LastSummary { get; private set; }

        public ulong LastCommittedInputStartedCount { get; private set; }

        public ulong LastCommittedDeclaredInputCount { get; private set; }

        public ulong LastCommittedInputCompletedCount { get; private set; }

        public ulong LastCommittedOutputStartedCount { get; private set; }

        public ulong LastCommittedOutputCompletedCount { get; private set; }

        public ulong LastCommittedDeclaredOutputCount { get; private set; }

        public ulong LastCommittedInputScriptBytes { get; private set; }

        public ulong LastCommittedOutputScriptBytes { get; private set; }

        public void OnTransactionStarted(int version, ulong inputCount)
        {
            if (_inputStartedCount != 0 ||
                _inputCompletedCount != 0 ||
                _outputStartedCount != 0 ||
                _outputCompletedCount != 0 ||
                _inputScriptBytes != 0 ||
                _outputScriptBytes != 0 ||
                _declaredInputCount != 0)
            {
                throw new InvalidOperationException("A prior provisional transaction was not reset.");
            }

            _declaredInputCount = inputCount;
        }

        public void OnInputStarted(ulong inputIndex, in OutPoint previousOutput, ulong scriptLength)
        {
            if (inputIndex != _inputStartedCount)
            {
                throw new InvalidOperationException("Input callback order was replayed or skipped.");
            }

            _inputStartedCount++;
        }

        public void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script) =>
            _inputScriptBytes = checked(_inputScriptBytes + (ulong)script.Length);

        public void OnInputCompleted(ulong inputIndex, uint sequence)
        {
            if (inputIndex != _inputCompletedCount)
            {
                throw new InvalidOperationException("Input completion order was replayed or skipped.");
            }

            _inputCompletedCount++;
        }

        public void OnOutputsStarted(ulong outputCount)
        {
            if (_declaredOutputCount != 0)
            {
                throw new InvalidOperationException("Outputs-started callback was replayed.");
            }

            _declaredOutputCount = outputCount;
        }

        public void OnOutputStarted(ulong outputIndex, long valueSatoshis, ulong scriptLength)
        {
            if (outputIndex != _outputStartedCount)
            {
                throw new InvalidOperationException("Output callback order was replayed or skipped.");
            }

            _outputStartedCount++;
        }

        public void OnOutputScriptChunk(ulong outputIndex, ReadOnlySpan<byte> script) =>
            _outputScriptBytes = checked(_outputScriptBytes + (ulong)script.Length);

        public void OnOutputCompleted(ulong outputIndex)
        {
            if (outputIndex != _outputCompletedCount)
            {
                throw new InvalidOperationException("Output completion order was replayed or skipped.");
            }

            _outputCompletedCount++;
        }

        public void OnTransactionCommitted(in LegacyTransactionSummary summary)
        {
            LastSummary = summary;
            LastCommittedDeclaredInputCount = _declaredInputCount;
            LastCommittedDeclaredOutputCount = _declaredOutputCount;
            LastCommittedInputStartedCount = _inputStartedCount;
            LastCommittedInputCompletedCount = _inputCompletedCount;
            LastCommittedOutputStartedCount = _outputStartedCount;
            LastCommittedOutputCompletedCount = _outputCompletedCount;
            LastCommittedInputScriptBytes = _inputScriptBytes;
            LastCommittedOutputScriptBytes = _outputScriptBytes;
            CommittedCount++;
            ResetProvisional();
        }

        public void OnTransactionAborted() => ResetProvisional();

        private void ResetProvisional()
        {
            _inputStartedCount = 0;
            _inputCompletedCount = 0;
            _outputStartedCount = 0;
            _outputCompletedCount = 0;
            _inputScriptBytes = 0;
            _outputScriptBytes = 0;
            _declaredInputCount = 0;
            _declaredOutputCount = 0;
        }
    }
}
