using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Transport;

namespace Staffetta.Core.Tests.Protocol.Transport;

[TestClass]
public sealed class BsvPeerStreamTransportFailureTests
{
    [TestMethod]
    public async Task CanceledPeerReadTerminalizesAndDisposesStreamOnce()
    {
        var source = CreateSource(out _);
        await using var fixture = await BsvPeerStreamTransportTestInfrastructure.CreateReadyAsync(
            new BufferPayloadSourceProvider(source));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var terminal = await fixture.Pump.StepAsync(cancellation.Token);

        Assert.AreEqual(BsvPeerTransportStepKind.Canceled, terminal.Kind);
        Assert.AreEqual(BsvPeerTransportTerminalReason.Canceled, terminal.Reason);
        Assert.AreEqual(1, fixture.Stream.DisposeCount);
        Assert.AreEqual(0, source.DisposeCount);
        Assert.AreEqual(0, fixture.Facts.AnnouncedCount);
        Assert.AreEqual(0, fixture.Facts.SentToPeerCount);
    }

    [TestMethod]
    public async Task PeerReadExceptionHasExactReasonAndDisposesStreamOnce()
    {
        var source = CreateSource(out _);
        await using var fixture = await BsvPeerStreamTransportTestInfrastructure.CreateReadyAsync(
            new BufferPayloadSourceProvider(source));
        fixture.Stream.ThrowOnRead = true;

        var terminal = await fixture.Pump.StepAsync();

        Assert.AreEqual(BsvPeerTransportStepKind.Faulted, terminal.Kind);
        Assert.AreEqual(BsvPeerTransportTerminalReason.TransportReadFailure, terminal.Reason);
        Assert.AreEqual(1, fixture.Stream.DisposeCount);
        Assert.AreEqual(0, source.DisposeCount);
    }

    [TestMethod]
    public async Task SourceOpenExceptionPublishesNoSentFact()
    {
        var source = CreateSource(out var transactionId);
        var provider = new BufferPayloadSourceProvider(source) { ThrowOnOpen = true };
        await using var fixture = await BsvPeerStreamTransportTestInfrastructure.CreateReadyAsync(provider);
        await BsvPeerStreamTransportTestInfrastructure.PrepareBroadcastAsync(
            fixture,
            transactionId);

        var terminal = await BsvPeerStreamTransportTestInfrastructure.RunUntilTerminalAsync(
            fixture.Pump);

        Assert.AreEqual(BsvPeerTransportTerminalReason.TransactionSourceFailure, terminal.Reason);
        Assert.AreEqual(1, fixture.Facts.AnnouncedCount);
        Assert.AreEqual(1, fixture.Facts.RequestedByPeerCount);
        Assert.AreEqual(0, fixture.Facts.SentToPeerCount);
        Assert.AreEqual(0, source.DisposeCount);
        Assert.AreEqual(1, fixture.Stream.DisposeCount);
    }

    [TestMethod]
    public async Task SourceReadExceptionTerminalizesAfterAnnouncementWithoutSentFact()
    {
        var source = CreateSource(out var transactionId);
        source.ThrowOnRead = true;
        await using var fixture = await BsvPeerStreamTransportTestInfrastructure.CreateReadyAsync(
            new BufferPayloadSourceProvider(source));
        await BsvPeerStreamTransportTestInfrastructure.PrepareBroadcastAsync(
            fixture,
            transactionId);

        var terminal = await BsvPeerStreamTransportTestInfrastructure.RunUntilTerminalAsync(
            fixture.Pump);

        Assert.AreEqual(BsvPeerTransportTerminalReason.TransactionSourceFailure, terminal.Reason);
        Assert.AreEqual(1, source.ReadCount);
        Assert.AreEqual(1, source.DisposeCount);
        Assert.AreEqual(1, fixture.Facts.AnnouncedCount);
        Assert.AreEqual(0, fixture.Facts.SentToPeerCount);
        Assert.AreEqual(1, fixture.Stream.DisposeCount);
    }

    [TestMethod]
    public async Task CanceledSourceReadHasCanceledReasonAndNoSentFact()
    {
        var source = CreateSource(out var transactionId);
        await using var fixture = await BsvPeerStreamTransportTestInfrastructure.CreateReadyAsync(
            new BufferPayloadSourceProvider(source));
        await BsvPeerStreamTransportTestInfrastructure.PrepareBroadcastAsync(
            fixture,
            transactionId);
        AssertProgress(await fixture.Pump.StepAsync());
        AssertProgress(await fixture.Pump.StepAsync());
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var terminal = await fixture.Pump.StepAsync(cancellation.Token);

        Assert.AreEqual(BsvPeerTransportStepKind.Canceled, terminal.Kind);
        Assert.AreEqual(BsvPeerTransportTerminalReason.Canceled, terminal.Reason);
        Assert.AreEqual(0, source.ReadCount);
        Assert.AreEqual(1, source.DisposeCount);
        Assert.AreEqual(0, fixture.Facts.SentToPeerCount);
        Assert.AreEqual(1, fixture.Stream.DisposeCount);
    }

    [TestMethod]
    public async Task CanceledWriteDoesNotCommitAnnouncement()
    {
        var source = CreateSource(out var transactionId);
        await using var fixture = await BsvPeerStreamTransportTestInfrastructure.CreateReadyAsync(
            new BufferPayloadSourceProvider(source));
        Assert.AreEqual(OperationStatus.Done, fixture.Pump.StartBroadcast(transactionId));
        AssertProgress(await fixture.Pump.StepAsync());
        var bytesBeforeCanceledWrite = fixture.Stream.WrittenByteCount;
        var writesBeforeCanceledWrite = fixture.Stream.WriteCallCount;
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var terminal = await fixture.Pump.StepAsync(cancellation.Token);
        var repeated = await fixture.Pump.StepAsync();

        Assert.AreEqual(BsvPeerTransportStepKind.Canceled, terminal.Kind);
        Assert.AreEqual(BsvPeerTransportTerminalReason.Canceled, terminal.Reason);
        Assert.AreEqual(terminal, repeated);
        Assert.AreEqual(bytesBeforeCanceledWrite, fixture.Stream.WrittenByteCount);
        Assert.AreEqual(writesBeforeCanceledWrite + 1, fixture.Stream.WriteCallCount);
        Assert.AreEqual(0, fixture.Facts.AnnouncedCount);
        Assert.AreEqual(0, fixture.Facts.SentToPeerCount);
        Assert.AreEqual(1, fixture.Stream.DisposeCount);
    }

    [TestMethod]
    public async Task WriteSideEffectThenCancellationIsAmbiguousAndNeverRetried()
    {
        var source = CreateSource(out var transactionId);
        await using var fixture = await BsvPeerStreamTransportTestInfrastructure.CreateReadyAsync(
            new BufferPayloadSourceProvider(source));
        Assert.AreEqual(OperationStatus.Done, fixture.Pump.StartBroadcast(transactionId));
        AssertProgress(await fixture.Pump.StepAsync());
        var bytesBeforeCanceledWrite = fixture.Stream.WrittenByteCount;
        var writesBeforeCanceledWrite = fixture.Stream.WriteCallCount;
        using var cancellation = new CancellationTokenSource();
        fixture.Stream.CancelWriteAfterSideEffectWith = cancellation;

        var terminal = await fixture.Pump.StepAsync(cancellation.Token);
        var repeated = await fixture.Pump.StepAsync();

        Assert.AreEqual(BsvPeerTransportStepKind.Canceled, terminal.Kind);
        Assert.AreEqual(BsvPeerTransportTerminalReason.Canceled, terminal.Reason);
        Assert.AreEqual(terminal, repeated);
        Assert.IsTrue(fixture.Stream.WrittenByteCount > bytesBeforeCanceledWrite);
        Assert.AreEqual(writesBeforeCanceledWrite + 1, fixture.Stream.WriteCallCount);
        Assert.AreEqual(0, fixture.Facts.AnnouncedCount);
        Assert.AreEqual(0, fixture.Facts.SentToPeerCount);
        Assert.AreEqual(1, fixture.Stream.DisposeCount);
    }

    [TestMethod]
    public async Task ThrowingWriteDoesNotCommitAnnouncement()
    {
        var source = CreateSource(out var transactionId);
        await using var fixture = await BsvPeerStreamTransportTestInfrastructure.CreateReadyAsync(
            new BufferPayloadSourceProvider(source));
        Assert.AreEqual(OperationStatus.Done, fixture.Pump.StartBroadcast(transactionId));
        AssertProgress(await fixture.Pump.StepAsync());
        fixture.Stream.ThrowOnWrite = true;

        var terminal = await fixture.Pump.StepAsync();

        Assert.AreEqual(BsvPeerTransportStepKind.Faulted, terminal.Kind);
        Assert.AreEqual(BsvPeerTransportTerminalReason.TransportWriteFailure, terminal.Reason);
        Assert.AreEqual(0, fixture.Facts.AnnouncedCount);
        Assert.AreEqual(0, fixture.Facts.SentToPeerCount);
        Assert.AreEqual(1, fixture.Stream.DisposeCount);
    }

    [TestMethod]
    public async Task SourceOverReturnIsAContractViolationAndDisposesOnce()
    {
        var source = CreateSource(out var transactionId);
        source.OverReturn = true;
        await using var fixture = await BsvPeerStreamTransportTestInfrastructure.CreateReadyAsync(
            new BufferPayloadSourceProvider(source));
        await BsvPeerStreamTransportTestInfrastructure.PrepareBroadcastAsync(
            fixture,
            transactionId);

        var terminal = await BsvPeerStreamTransportTestInfrastructure.RunUntilTerminalAsync(
            fixture.Pump);

        Assert.AreEqual(
            BsvPeerTransportTerminalReason.TransactionSourceContractViolation,
            terminal.Reason);
        Assert.AreEqual(1, source.ReadCount);
        Assert.AreEqual(1, source.DisposeCount);
        Assert.AreEqual(0, fixture.Facts.SentToPeerCount);
        Assert.AreEqual(1, fixture.Stream.DisposeCount);
    }

    [TestMethod]
    public async Task SourceReadSideEffectThenCancellationProvidesNoPayloadAndPublishesNoSentFact()
    {
        var source = CreateSource(out var transactionId);
        await using var fixture = await BsvPeerStreamTransportTestInfrastructure.CreateReadyAsync(
            new BufferPayloadSourceProvider(source));
        await BsvPeerStreamTransportTestInfrastructure.PrepareBroadcastAsync(
            fixture,
            transactionId);
        AssertProgress(await fixture.Pump.StepAsync());
        AssertProgress(await fixture.Pump.StepAsync());
        var bytesAfterTransactionHeader = fixture.Stream.WrittenByteCount;
        using var cancellation = new CancellationTokenSource();
        source.CancelReadAfterMutationWith = cancellation;

        var terminal = await fixture.Pump.StepAsync(cancellation.Token);

        Assert.AreEqual(BsvPeerTransportStepKind.Canceled, terminal.Kind);
        Assert.AreEqual(BsvPeerTransportTerminalReason.Canceled, terminal.Reason);
        Assert.AreEqual(1, source.ReadCount);
        Assert.AreEqual(1, source.MutatedByteCount);
        Assert.AreEqual(bytesAfterTransactionHeader, fixture.Stream.WrittenByteCount);
        Assert.AreEqual(1, source.DisposeCount);
        Assert.AreEqual(0, fixture.Facts.SentToPeerCount);
        Assert.AreEqual(1, fixture.Stream.DisposeCount);
    }

    [TestMethod]
    public async Task CleanupFailuresPreservePrimarySourceReadFailureAndAttemptBothDisposals()
    {
        var source = CreateSource(out var transactionId);
        source.ThrowOnRead = true;
        source.ThrowOnDispose = true;
        await using var fixture = await BsvPeerStreamTransportTestInfrastructure.CreateReadyAsync(
            new BufferPayloadSourceProvider(source));
        fixture.Stream.ThrowOnDispose = true;
        await BsvPeerStreamTransportTestInfrastructure.PrepareBroadcastAsync(
            fixture,
            transactionId);

        var terminal = await BsvPeerStreamTransportTestInfrastructure.RunUntilTerminalAsync(
            fixture.Pump);

        Assert.AreEqual(BsvPeerTransportStepKind.Faulted, terminal.Kind);
        Assert.AreEqual(BsvPeerTransportTerminalReason.TransactionSourceFailure, terminal.Reason);
        Assert.AreEqual(1, source.DisposeCount);
        Assert.AreEqual(1, fixture.Stream.DisposeCount);
        Assert.AreEqual(0, fixture.Facts.SentToPeerCount);
    }

    private static CountingPayloadSource CreateSource(out Hash256 transactionId)
    {
        byte[] payload = [1, 2, 3, 4, 5, 6, 7, 8];
        transactionId = Hash256.DoubleSha256(payload);
        return new CountingPayloadSource(transactionId, (ulong)payload.Length, payload);
    }

    private static void AssertProgress(BsvPeerTransportStepResult result) =>
        Assert.AreEqual(
            BsvPeerTransportStepKind.Progress,
            result.Kind,
            $"Unexpected terminal reason: {result.Reason}.");
}
