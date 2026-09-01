using System.Buffers;
using System.Buffers.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Transactions;

namespace Staffetta.Core.Tests.Protocol.Transactions;

[TestClass]
public sealed class BsvTransactionMonetaryRangeValidatorTests
{
    private const long MaximumMoney = BsvTransactionMonetaryRangeValidator.MaximumMoneySatoshis;

    [TestMethod]
    [DataRow(-1L, (int)BsvTransactionMonetaryValidationReason.NegativeOutput)]
    [DataRow(MaximumMoney + 1, (int)BsvTransactionMonetaryValidationReason.OutputExceedsMaximum)]
    [DataRow(long.MaxValue, (int)BsvTransactionMonetaryValidationReason.OutputExceedsMaximum)]
    public void InvalidPerOutputBoundariesAbortDownstreamOnlyAfterCommit(
        long value,
        int expectedReason)
    {
        var transaction = CreateTransaction([value]);
        var sink = new RecordingSink();
        var validator = new BsvTransactionMonetaryRangeValidator(sink);
        using var parser = new LegacyTransactionParser(validator);

        Assert.AreEqual(OperationStatus.Done, parser.Consume(transaction, out var consumed));
        Assert.AreEqual(transaction.Length, consumed);
        Assert.IsFalse(validator.TryGetCommittedValidation(out _));
        Assert.AreEqual(0, sink.AbortedCount);
        Assert.AreEqual(0, sink.CommittedCount);

        Assert.AreEqual(OperationStatus.Done, parser.Commit(out var summary));
        Assert.IsTrue(validator.TryGetCommittedValidation(out var validation));
        Assert.AreEqual(summary.TransactionId, validation.TransactionId);
        Assert.AreEqual((BsvTransactionMonetaryValidationReason)expectedReason, validation.Reason);
        Assert.AreEqual(value, validation.OutputValueSatoshis);
        Assert.AreEqual(1, sink.AbortedCount);
        Assert.AreEqual(0, sink.CommittedCount);
    }

    [TestMethod]
    [DataRow(0L)]
    [DataRow(MaximumMoney)]
    public void ValidPerOutputBoundariesCommitDownstream(long value)
    {
        var validation = ParseAndCommit([value], out var sink);

        Assert.IsTrue(validation.IsValid);
        Assert.AreEqual(BsvTransactionMonetaryValidationReason.None, validation.Reason);
        Assert.AreEqual(value, validation.TotalOutputValueSatoshis);
        Assert.AreEqual(1, sink.CommittedCount);
        Assert.AreEqual(0, sink.AbortedCount);
    }

    [TestMethod]
    public void AggregateBoundaryAcceptsMaximumAndRejectsMaximumPlusOneWithoutOverflow()
    {
        var accepted = ParseAndCommit([MaximumMoney - 1, 1], out var acceptedSink);
        Assert.IsTrue(accepted.IsValid);
        Assert.AreEqual(MaximumMoney, accepted.TotalOutputValueSatoshis);
        Assert.AreEqual(1, acceptedSink.CommittedCount);

        var rejected = ParseAndCommit([MaximumMoney, 1], out var rejectedSink);
        Assert.AreEqual(
            BsvTransactionMonetaryValidationReason.AggregateExceedsMaximum,
            rejected.Reason);
        Assert.AreEqual<ulong>(1, rejected.OutputIndex);
        Assert.AreEqual(1, rejected.OutputValueSatoshis);
        Assert.AreEqual(MaximumMoney + 1, rejected.TotalOutputValueSatoshis);
        Assert.AreEqual(1, rejectedSink.AbortedCount);
        Assert.AreEqual(0, rejectedSink.CommittedCount);
    }

    [TestMethod]
    public void ParserAbortPublishesNoVerdictAndDelegatesOneAbort()
    {
        var transaction = CreateTransaction([1]);
        var sink = new RecordingSink();
        var validator = new BsvTransactionMonetaryRangeValidator(sink);
        using var parser = new LegacyTransactionParser(validator);

        Assert.AreEqual(
            OperationStatus.NeedMoreData,
            parser.Consume(transaction.AsSpan(0, transaction.Length - 1), out _));
        parser.Abort();

        Assert.IsFalse(validator.TryGetCommittedValidation(out _));
        Assert.AreEqual(1, sink.AbortedCount);
        Assert.AreEqual(0, sink.CommittedCount);
    }

    [TestMethod]
    public void WarmManyOutputValidationHasNoAllocationSlope()
    {
        var small = CreateTransaction(new long[32]);
        var large = CreateTransaction(new long[16_384]);
        var sink = new RecordingSink();
        var validator = new BsvTransactionMonetaryRangeValidator(sink);
        using var parser = new LegacyTransactionParser(validator);

        ParseAndCommit(parser, small);
        ParseAndCommit(parser, large);

        var smallAllocated = MeasureAllocatedBytes(parser, small, iterations: 4);
        var largeAllocated = MeasureAllocatedBytes(parser, large, iterations: 4);

        Assert.AreEqual(smallAllocated, largeAllocated);
        Assert.AreEqual(0L, largeAllocated);
    }

    private static BsvTransactionMonetaryValidation ParseAndCommit(
        long[] values,
        out RecordingSink sink)
    {
        sink = new RecordingSink();
        var validator = new BsvTransactionMonetaryRangeValidator(sink);
        using var parser = new LegacyTransactionParser(validator);
        var transaction = CreateTransaction(values);

        ParseAndCommit(parser, transaction);
        Assert.IsTrue(validator.TryGetCommittedValidation(out var validation));
        return validation;
    }

    private static void ParseAndCommit(LegacyTransactionParser parser, byte[] transaction)
    {
        Assert.AreEqual(OperationStatus.Done, parser.Consume(transaction, out var consumed));
        Assert.AreEqual(transaction.Length, consumed);
        Assert.AreEqual(OperationStatus.Done, parser.Commit(out _));
    }

    private static long MeasureAllocatedBytes(
        LegacyTransactionParser parser,
        byte[] transaction,
        int iterations)
    {
        var succeeded = true;
        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var iteration = 0; iteration < iterations; iteration++)
        {
            succeeded &= parser.Consume(transaction, out var consumed) == OperationStatus.Done;
            succeeded &= consumed == transaction.Length;
            succeeded &= parser.Commit(out _) == OperationStatus.Done;
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.IsTrue(succeeded);
        return allocated;
    }

    private static byte[] CreateTransaction(long[] values)
    {
        Assert.IsTrue(values.Length is > 0 and <= ushort.MaxValue);
        var outputCountLength = values.Length < 0xfd ? 1 : 3;
        const int inputLength = Hash256.Length + sizeof(uint) + 1 + sizeof(uint);
        const int outputLength = sizeof(long) + 1;
        var transaction = new byte[
            sizeof(int) + 1 + inputLength + outputCountLength +
            (values.Length * outputLength) + sizeof(uint)];
        var offset = 0;
        BinaryPrimitives.WriteInt32LittleEndian(transaction.AsSpan(offset), 1);
        offset += sizeof(int);
        transaction[offset++] = 1;
        offset += Hash256.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(offset), uint.MaxValue);
        offset += sizeof(uint);
        transaction[offset++] = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(offset), uint.MaxValue);
        offset += sizeof(uint);
        if (values.Length < 0xfd)
        {
            transaction[offset++] = (byte)values.Length;
        }
        else
        {
            transaction[offset++] = 0xfd;
            BinaryPrimitives.WriteUInt16LittleEndian(transaction.AsSpan(offset), (ushort)values.Length);
            offset += sizeof(ushort);
        }

        foreach (var value in values)
        {
            BinaryPrimitives.WriteInt64LittleEndian(transaction.AsSpan(offset), value);
            offset += sizeof(long);
            transaction[offset++] = 0;
        }

        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(offset), 0);
        offset += sizeof(uint);
        Assert.AreEqual(transaction.Length, offset);
        return transaction;
    }

    private sealed class RecordingSink : ILegacyTransactionSink
    {
        internal int CommittedCount { get; private set; }

        internal int AbortedCount { get; private set; }

        public void OnTransactionStarted(int version, ulong inputCount) { }

        public void OnInputStarted(ulong inputIndex, in OutPoint previousOutput, ulong scriptLength) { }

        public void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script) { }

        public void OnInputCompleted(ulong inputIndex, uint sequence) { }

        public void OnOutputsStarted(ulong outputCount) { }

        public void OnOutputStarted(ulong outputIndex, long valueSatoshis, ulong scriptLength) { }

        public void OnOutputScriptChunk(ulong outputIndex, ReadOnlySpan<byte> script) { }

        public void OnOutputCompleted(ulong outputIndex) { }

        public void OnTransactionCommitted(in LegacyTransactionSummary summary) => CommittedCount++;

        public void OnTransactionAborted() => AbortedCount++;
    }
}
