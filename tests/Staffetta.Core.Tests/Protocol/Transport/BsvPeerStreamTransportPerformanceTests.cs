using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Transport;

namespace Staffetta.Core.Tests.Protocol.Transport;

[TestClass]
public sealed class BsvPeerStreamTransportPerformanceTests
{
    private const int MeasurementRuns = 5;
    private const long MaximumAllocationSlopeBytes = 1024;

    private static readonly byte[] SmallPayload = CreatePayload(64 * 1024);
    private static readonly byte[] LargePayload = CreatePayload(8 * 1024 * 1024);

    [TestMethod]
    public async Task TransactionCompletionAllocationDoesNotScaleWithPayloadChunks()
    {
#if DEBUG
        await ValueTask.CompletedTask;
        Assert.Inconclusive(
            "Allocation slope evidence is Release-only; Debug async instrumentation measured per-step allocations.");
        return;
#else
        await using (var warmSmall = await PrepareAsync(SmallPayload))
        {
            _ = await MeasureCompletionAllocationsAsync(warmSmall);
        }

        await using (var warmLarge = await PrepareAsync(LargePayload))
        {
            _ = await MeasureCompletionAllocationsAsync(warmLarge);
        }

        for (var run = 0; run < MeasurementRuns; run++)
        {
            await using var small = await PrepareAsync(SmallPayload);
            await using var large = await PrepareAsync(LargePayload);

            var smallBytes = await MeasureCompletionAllocationsAsync(small);
            var largeBytes = await MeasureCompletionAllocationsAsync(large);
            Console.WriteLine(
                $"allocation-run={run + 1} small={smallBytes} large={largeBytes} delta={largeBytes - smallBytes}");

            Assert.IsTrue(
                largeBytes <= smallBytes + MaximumAllocationSlopeBytes,
                $"Managed allocation scaled with transaction chunks on run {run + 1}: " +
                $"small={smallBytes}, large={largeBytes}.");
        }
#endif
    }

    [TestMethod]
    public async Task AllocationHarnessDetectsAControlSourceThatAllocatesPerChunk()
    {
#if DEBUG
        await ValueTask.CompletedTask;
        Assert.Inconclusive(
            "Allocation sensitivity evidence is Release-only; Debug async instrumentation is not the production baseline.");
        return;
#else
        await using var small = await PrepareAsync(SmallPayload, allocatePerRead: true);
        await using var large = await PrepareAsync(LargePayload, allocatePerRead: true);

        var smallBytes = await MeasureCompletionAllocationsAsync(small);
        var largeBytes = await MeasureCompletionAllocationsAsync(large);

        Assert.IsTrue(
            largeBytes > smallBytes + 32 * 1024,
            "The allocation harness did not detect a deliberately allocating per-read source.");
#endif
    }

    [TestMethod]
    public async Task DeclaredPayloadAboveFourGiBIsRejectedBeforeHeaderOrSourceRead()
    {
        const ulong declaredLength = (ulong)uint.MaxValue + 65_537;
        var transactionId = Hash256.DoubleSha256("over-four-gib"u8);
        var source = new CountingPayloadSource(transactionId, declaredLength);
        await using var fixture = await BsvPeerStreamTransportTestInfrastructure.CreateReadyAsync(
            new BufferPayloadSourceProvider(source),
            peerMaximumReceivePayloadLength: uint.MaxValue);
        await BsvPeerStreamTransportTestInfrastructure.PrepareBroadcastAsync(
            fixture,
            transactionId);
        var bytesBeforeTransactionPlan = fixture.Stream.WrittenByteCount;

        var terminal = await BsvPeerStreamTransportTestInfrastructure.RunUntilTerminalAsync(
            fixture.Pump);

        Assert.AreEqual(BsvPeerTransportStepKind.Faulted, terminal.Kind);
        Assert.AreEqual(
            BsvPeerTransportTerminalReason.TransactionSourceContractViolation,
            terminal.Reason);
        Assert.AreEqual(bytesBeforeTransactionPlan, fixture.Stream.WrittenByteCount);
        Assert.AreEqual(0, source.ReadCount);
        Assert.AreEqual(1, source.DisposeCount);
        Assert.AreEqual(1, fixture.Facts.AnnouncedCount);
        Assert.AreEqual(1, fixture.Facts.RequestedByPeerCount);
        Assert.AreEqual(0, fixture.Facts.SentToPeerCount);
        Assert.AreEqual(1, fixture.Stream.DisposeCount);
    }

    private static async ValueTask<TransportFixture> PrepareAsync(
        byte[] payload,
        bool allocatePerRead = false)
    {
        var transactionId = Hash256.DoubleSha256(payload);
        IBsvTransactionPayloadSource source = allocatePerRead
            ? new AllocatingPayloadSource(transactionId, payload)
            : new CountingPayloadSource(transactionId, (ulong)payload.Length, payload);
        var fixture = await BsvPeerStreamTransportTestInfrastructure.CreateReadyAsync(
            new BufferPayloadSourceProvider(source),
            new BsvPeerStreamTransportOptions(
                readBufferLength: 16 * 1024,
                transactionBufferLength: 16 * 1024,
                maximumWriteLength: 64 * 1024,
                leaveOpen: false));
        await BsvPeerStreamTransportTestInfrastructure.PrepareBroadcastAsync(
            fixture,
            transactionId);
        return fixture;
    }

    private static async ValueTask<long> MeasureCompletionAllocationsAsync(
        TransportFixture fixture)
    {
        var threadId = Environment.CurrentManagedThreadId;
        var before = GC.GetAllocatedBytesForCurrentThread();
        while (fixture.Facts.SentToPeerCount == 0)
        {
            var result = await fixture.Pump.StepAsync().ConfigureAwait(false);
            if (Environment.CurrentManagedThreadId != threadId)
            {
                throw new AssertFailedException(
                    "The allocation evidence switched threads on the synchronous test path.");
            }

            if (result.Kind != BsvPeerTransportStepKind.Progress)
            {
                throw new AssertFailedException(
                    "The transport became terminal inside the allocation measurement.");
            }
        }

        return GC.GetAllocatedBytesForCurrentThread() - before;
    }

    private static byte[] CreatePayload(int length)
    {
        var payload = new byte[length];
        for (var index = 0; index < payload.Length; index++)
        {
            payload[index] = (byte)(index * 31);
        }

        return payload;
    }

    private sealed class AllocatingPayloadSource : IBsvTransactionPayloadSource
    {
        private readonly byte[] _payload;
        private int _offset;

        internal AllocatingPayloadSource(Hash256 transactionId, byte[] payload)
        {
            TransactionId = transactionId;
            Length = (ulong)payload.Length;
            _payload = payload;
        }

        public Hash256 TransactionId { get; }

        public ulong Length { get; }

        public ValueTask<int> ReadAsync(
            Memory<byte> destination,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var deliberateAllocation = new byte[128];
            GC.KeepAlive(deliberateAllocation);
            var length = Math.Min(destination.Length, _payload.Length - _offset);
            _payload.AsSpan(_offset, length).CopyTo(destination.Span);
            _offset += length;
            return ValueTask.FromResult(length);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
