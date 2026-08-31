using System.Buffers;
using System.Buffers.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Transactions;

namespace Staffetta.Core.Tests.Protocol.Transactions;

[TestClass]
public sealed class LegacyTransactionParserTests
{
    private const string ExpectedTransactionId =
        "692d0e489d19dca764d6285051c35f6fa6c360fd50082baa4e1732519c785d4f";

    [TestMethod]
    public void CanonicalTransactionParsesAcrossEveryTwoChunkAndByteBoundary()
    {
        var transaction = CreateTransaction();
        for (var split = 0; split <= transaction.Length; split++)
        {
            var sink = new RecordingSink();
            using var parser = new LegacyTransactionParser(sink);

            AssertChunk(parser, transaction.AsSpan(0, split), split == transaction.Length);
            AssertChunk(parser, transaction.AsSpan(split), expectedDone: true);
            AssertCommitted(parser, sink, transaction);
        }

        var bytewiseSink = new RecordingSink();
        using var bytewiseParser = new LegacyTransactionParser(bytewiseSink);
        for (var index = 0; index < transaction.Length; index++)
        {
            AssertChunk(
                bytewiseParser,
                transaction.AsSpan(index, 1),
                expectedDone: index == transaction.Length - 1);
        }

        AssertCommitted(bytewiseParser, bytewiseSink, transaction);
        CollectionAssert.AreEqual(new byte[] { 0xaa, 0xbb }, bytewiseSink.InputScript.ToArray());
        CollectionAssert.AreEqual(new byte[] { 0x51, 0x52, 0x53 }, bytewiseSink.OutputScript.ToArray());
        Assert.AreEqual(2, bytewiseSink.InputScriptChunkCount);
        Assert.AreEqual(3, bytewiseSink.OutputScriptChunkCount);
    }

    [TestMethod]
    public void ParserRejectsNonCanonicalZeroCountsAndWitnessMarker()
    {
        AssertInvalid([1, 0, 0, 0, 0]);
        AssertInvalid([1, 0, 0, 0, 0, 1]);
        AssertInvalid([1, 0, 0, 0, 0xfd, 1, 0]);

        var zeroOutputs = CreateTransaction();
        zeroOutputs[4 + 1 + 36 + 1 + 2 + 4] = 0;
        AssertInvalid(zeroOutputs);

        var nonCanonicalOutputs = CreateTransaction();
        var outputCountOffset = 4 + 1 + 36 + 1 + 2 + 4;
        var expanded = new byte[nonCanonicalOutputs.Length + 2];
        nonCanonicalOutputs.AsSpan(0, outputCountOffset).CopyTo(expanded);
        expanded[outputCountOffset] = 0xfd;
        expanded[outputCountOffset + 1] = 1;
        nonCanonicalOutputs.AsSpan(outputCountOffset + 1).CopyTo(expanded.AsSpan(outputCountOffset + 3));
        AssertInvalid(expanded);
    }

    [TestMethod]
    public void ParserStreamsHighInputCountWithoutRetainingRecords()
    {
        const int inputCount = 4_000;
        var transaction = CreateHighInputCountTransaction(inputCount);
        var sink = new CountingSink();
        using var parser = new LegacyTransactionParser(sink);

        var offset = 0;
        while (offset < transaction.Length)
        {
            var length = Math.Min(137, transaction.Length - offset);
            var status = parser.Consume(transaction.AsSpan(offset, length), out var consumed);
            Assert.AreEqual(length, consumed);
            offset += consumed;
            if (offset < transaction.Length)
            {
                Assert.AreEqual(OperationStatus.NeedMoreData, status);
            }
        }

        Assert.IsTrue(parser.IsReadyToCommit);
        Assert.AreEqual(OperationStatus.Done, parser.Commit(out var summary));
        Assert.AreEqual<ulong>(inputCount, summary.InputCount);
        Assert.AreEqual(inputCount, sink.InputsCompleted);
        Assert.AreEqual(1, sink.OutputsCompleted);
    }

    [TestMethod]
    public void ParserStopsAtTransactionBoundaryAndLeavesTrailingBytes()
    {
        var transaction = CreateTransaction();
        var framed = new byte[transaction.Length + 3];
        transaction.CopyTo(framed, 0);
        framed[^3] = 0xaa;
        framed[^2] = 0xbb;
        framed[^1] = 0xcc;

        var sink = new RecordingSink();
        using var parser = new LegacyTransactionParser(sink);
        Assert.AreEqual(
            OperationStatus.Done,
            parser.Consume(framed, out var consumed));
        Assert.AreEqual(transaction.Length, consumed);
        AssertCommitted(parser, sink, transaction);
    }

    [TestMethod]
    public void AbortDiscardsLifecycleAndResetsParser()
    {
        var transaction = CreateTransaction();
        var sink = new RecordingSink();
        using var parser = new LegacyTransactionParser(sink);

        Assert.AreEqual(
            OperationStatus.NeedMoreData,
            parser.Consume(transaction.AsSpan(0, 10), out var consumed));
        Assert.AreEqual(10, consumed);
        parser.Abort();
        Assert.AreEqual(1, sink.AbortCount);
        Assert.IsFalse(parser.IsFaulted);

        AssertChunk(parser, transaction, expectedDone: true);
        AssertCommitted(parser, sink, transaction, expectedAbortCount: 1);
    }

    [TestMethod]
    public void MalformedInputAndSinkExceptionFaultPermanently()
    {
        var sink = new RecordingSink();
        using var malformed = new LegacyTransactionParser(sink);
        Assert.AreEqual(OperationStatus.InvalidData, malformed.Consume([1, 0, 0, 0, 0], out _));
        Assert.IsTrue(malformed.IsFaulted);
        Assert.AreEqual(OperationStatus.InvalidData, malformed.Consume(CreateTransaction(), out var consumed));
        Assert.AreEqual(0, consumed);
        Assert.ThrowsException<InvalidOperationException>(malformed.Abort);

        var throwingSink = new ThrowingSink();
        using var throwing = new LegacyTransactionParser(throwingSink);
        Assert.ThrowsException<InvalidOperationException>(() => throwing.Consume(CreateTransaction(), out _));
        Assert.IsTrue(throwing.IsFaulted);
        Assert.AreEqual(0, throwingSink.AbortCount);
    }

    [TestMethod]
    public void SinkReentrancyFaultsParser()
    {
        var sink = new ReentrantSink();
        using var parser = new LegacyTransactionParser(sink);
        sink.Parser = parser;

        Assert.ThrowsException<InvalidOperationException>(() => parser.Consume(CreateTransaction(), out _));
        Assert.IsTrue(parser.IsFaulted);
    }

    [TestMethod]
    public void HashAcceptsScriptBytesBeforeSinkCanMutateBackingBuffer()
    {
        var transaction = CreateTransaction();
        var expectedTransactionId = Hash256.DoubleSha256(transaction);
        var sink = new MutatingScriptSink(transaction);
        using var parser = new LegacyTransactionParser(sink);

        Assert.AreEqual(OperationStatus.Done, parser.Consume(transaction, out var consumed));
        Assert.AreEqual(transaction.Length, consumed);
        Assert.AreEqual(OperationStatus.Done, parser.Commit(out var summary));

        Assert.IsTrue(sink.Mutated);
        Assert.AreEqual((byte)0x00, transaction[42]);
        Assert.AreEqual(expectedTransactionId, summary.TransactionId);
    }

    [TestMethod]
    public void WarmParserHasFlatAllocationAcrossHighCountsAndScriptChunks()
    {
        var transaction = CreateHighInputCountTransaction(512, includeScriptByte: true);
        var sink = new CountingSink();
        using var parser = new LegacyTransactionParser(sink);

        Assert.AreEqual(OperationStatus.Done, parser.Consume(transaction, out _));
        Assert.AreEqual(OperationStatus.Done, parser.Commit(out _));

        const int iterations = 8;
        var allSucceeded = true;
        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var iteration = 0; iteration < iterations; iteration++)
        {
            allSucceeded &= parser.Consume(transaction, out var consumed) == OperationStatus.Done;
            allSucceeded &= consumed == transaction.Length;
            allSucceeded &= parser.Commit(out _) == OperationStatus.Done;
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.IsTrue(allSucceeded);
        Assert.AreEqual(0L, allocated);
    }

    [TestMethod]
    public void CaughtReentrancyStillStopsOuterParserBeforeLaterCallbacks()
    {
        var sink = new CaughtReentrantSink();
        using var parser = new LegacyTransactionParser(sink);
        sink.Parser = parser;

        Assert.ThrowsException<InvalidOperationException>(() => parser.Consume(CreateTransaction(), out _));
        Assert.AreEqual(1, sink.CaughtReentryCount);
        Assert.AreEqual(0, sink.InputStartedCount);
        Assert.IsTrue(parser.IsFaulted);
    }

    [TestMethod]
    public void ThrowingScriptCallbackReportsAcceptedBytesAndNeverReplaysChunk()
    {
        var transaction = CreateTransaction();
        var sink = new ThrowingSink();
        using var parser = new LegacyTransactionParser(sink);
        var consumed = -1;

        Assert.ThrowsException<InvalidOperationException>(() => parser.Consume(transaction, out consumed));
        Assert.AreEqual(44, consumed);
        Assert.AreEqual(1, sink.ScriptCallbackCount);
        Assert.IsTrue(parser.IsFaulted);

        Assert.AreEqual(OperationStatus.InvalidData, parser.Consume(transaction, out consumed));
        Assert.AreEqual(0, consumed);
        Assert.AreEqual(1, sink.ScriptCallbackCount);
    }

    private static void AssertChunk(
        LegacyTransactionParser parser,
        ReadOnlySpan<byte> chunk,
        bool expectedDone)
    {
        var status = parser.Consume(chunk, out var consumed);
        Assert.AreEqual(chunk.Length, consumed);
        Assert.AreEqual(
            expectedDone ? OperationStatus.Done : OperationStatus.NeedMoreData,
            status);
    }

    private static void AssertCommitted(
        LegacyTransactionParser parser,
        RecordingSink sink,
        byte[] transaction,
        int expectedAbortCount = 0)
    {
        Assert.IsTrue(parser.IsReadyToCommit);
        Assert.AreEqual(OperationStatus.Done, parser.Commit(out var summary));
        Assert.AreEqual(ExpectedTransactionId, summary.TransactionId.ToDisplayHex());
        Assert.AreEqual(1, summary.Version);
        Assert.AreEqual<ulong>(1, summary.InputCount);
        Assert.AreEqual<ulong>(1, summary.OutputCount);
        Assert.AreEqual<ulong>(2, summary.TotalInputScriptLength);
        Assert.AreEqual<ulong>(3, summary.TotalOutputScriptLength);
        Assert.AreEqual<uint>(0, summary.LockTime);
        Assert.AreEqual<ulong>((ulong)transaction.Length, summary.SerializedLength);
        Assert.AreEqual(summary.TransactionId, Hash256.DoubleSha256(transaction));
        Assert.AreEqual(1, sink.CommitCount);
        Assert.AreEqual(expectedAbortCount, sink.AbortCount);
    }

    private static void AssertInvalid(byte[] transaction)
    {
        var sink = new RecordingSink();
        using var parser = new LegacyTransactionParser(sink);
        Assert.AreEqual(OperationStatus.InvalidData, parser.Consume(transaction, out _));
        Assert.IsTrue(parser.IsFaulted);
    }

    private static byte[] CreateTransaction()
    {
        var transaction = new byte[65];
        var offset = 0;
        BinaryPrimitives.WriteInt32LittleEndian(transaction.AsSpan(offset), 1);
        offset += sizeof(int);
        transaction[offset++] = 1;
        offset += Hash256.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(offset), uint.MaxValue);
        offset += sizeof(uint);
        transaction[offset++] = 2;
        transaction[offset++] = 0xaa;
        transaction[offset++] = 0xbb;
        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(offset), 0xffff_fffe);
        offset += sizeof(uint);
        transaction[offset++] = 1;
        BinaryPrimitives.WriteInt64LittleEndian(transaction.AsSpan(offset), 1_000);
        offset += sizeof(long);
        transaction[offset++] = 3;
        transaction[offset++] = 0x51;
        transaction[offset++] = 0x52;
        transaction[offset++] = 0x53;
        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(offset), 0);
        offset += sizeof(uint);
        Assert.AreEqual(transaction.Length, offset);
        return transaction;
    }

    private static byte[] CreateHighInputCountTransaction(
        int inputCount,
        bool includeScriptByte = false)
    {
        const int compactCountLength = 3;
        var scriptLength = includeScriptByte ? 1 : 0;
        var inputLength = Hash256.Length + sizeof(uint) + 1 + scriptLength + sizeof(uint);
        const int outputLength = sizeof(long) + 1;
        var transaction = new byte[
            sizeof(int) + compactCountLength + (inputCount * inputLength) + 1 + outputLength + sizeof(uint)];
        var offset = 0;
        BinaryPrimitives.WriteInt32LittleEndian(transaction.AsSpan(offset), 2);
        offset += sizeof(int);
        transaction[offset++] = 0xfd;
        BinaryPrimitives.WriteUInt16LittleEndian(transaction.AsSpan(offset), (ushort)inputCount);
        offset += sizeof(ushort);
        for (var index = 0; index < inputCount; index++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(
                transaction.AsSpan(offset + Hash256.Length),
                (uint)index);
            offset += Hash256.Length + sizeof(uint);
            transaction[offset++] = (byte)scriptLength;
            if (includeScriptByte)
            {
                transaction[offset++] = 0x51;
            }

            BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(offset), uint.MaxValue);
            offset += sizeof(uint);
        }

        transaction[offset++] = 1;
        BinaryPrimitives.WriteInt64LittleEndian(transaction.AsSpan(offset), 0);
        offset += sizeof(long);
        transaction[offset++] = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(offset), 0);
        offset += sizeof(uint);
        Assert.AreEqual(transaction.Length, offset);
        return transaction;
    }

    private class RecordingSink : ILegacyTransactionSink
    {
        public List<byte> InputScript { get; } = [];

        public List<byte> OutputScript { get; } = [];

        public int InputScriptChunkCount { get; private set; }

        public int OutputScriptChunkCount { get; private set; }

        public int CommitCount { get; private set; }

        public int AbortCount { get; private set; }

        public int InputStartedCount { get; private set; }

        public virtual void OnTransactionStarted(int version, ulong inputCount)
        {
        }

        public virtual void OnInputStarted(ulong inputIndex, in OutPoint previousOutput, ulong scriptLength)
        {
            InputStartedCount++;
        }

        public virtual void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script)
        {
            InputScriptChunkCount++;
            InputScript.AddRange(script);
        }

        public void OnInputCompleted(ulong inputIndex, uint sequence)
        {
        }

        public void OnOutputsStarted(ulong outputCount)
        {
        }

        public void OnOutputStarted(ulong outputIndex, long valueSatoshis, ulong scriptLength)
        {
        }

        public void OnOutputScriptChunk(ulong outputIndex, ReadOnlySpan<byte> script)
        {
            OutputScriptChunkCount++;
            OutputScript.AddRange(script);
        }

        public void OnOutputCompleted(ulong outputIndex)
        {
        }

        public void OnTransactionCommitted(in LegacyTransactionSummary summary) => CommitCount++;

        public void OnTransactionAborted() => AbortCount++;
    }

    private sealed class CountingSink : ILegacyTransactionSink
    {
        public int InputsCompleted { get; private set; }

        public int OutputsCompleted { get; private set; }

        public void OnTransactionStarted(int version, ulong inputCount)
        {
        }

        public void OnInputStarted(ulong inputIndex, in OutPoint previousOutput, ulong scriptLength)
        {
        }

        public void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script)
        {
        }

        public void OnInputCompleted(ulong inputIndex, uint sequence) => InputsCompleted++;

        public void OnOutputsStarted(ulong outputCount)
        {
        }

        public void OnOutputStarted(ulong outputIndex, long valueSatoshis, ulong scriptLength)
        {
        }

        public void OnOutputScriptChunk(ulong outputIndex, ReadOnlySpan<byte> script)
        {
        }

        public void OnOutputCompleted(ulong outputIndex) => OutputsCompleted++;

        public void OnTransactionCommitted(in LegacyTransactionSummary summary)
        {
        }

        public void OnTransactionAborted()
        {
        }
    }

    private sealed class ThrowingSink : RecordingSink
    {
        public int ScriptCallbackCount { get; private set; }

        public override void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script)
        {
            ScriptCallbackCount++;
            throw new InvalidOperationException("sink failure");
        }
    }

    private sealed class ReentrantSink : RecordingSink
    {
        public LegacyTransactionParser? Parser { get; set; }

        public override void OnTransactionStarted(int version, ulong inputCount) =>
            Parser!.Consume([], out _);
    }

    private sealed class CaughtReentrantSink : RecordingSink
    {
        public LegacyTransactionParser? Parser { get; set; }

        public int CaughtReentryCount { get; private set; }

        public override void OnTransactionStarted(int version, ulong inputCount)
        {
            try
            {
                Parser!.Consume([], out _);
            }
            catch (InvalidOperationException)
            {
                CaughtReentryCount++;
            }
        }
    }

    private sealed class MutatingScriptSink(byte[] backingBuffer) : RecordingSink
    {
        public bool Mutated { get; private set; }

        public override void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script)
        {
            backingBuffer[42] = 0;
            Mutated = true;
        }
    }
}
