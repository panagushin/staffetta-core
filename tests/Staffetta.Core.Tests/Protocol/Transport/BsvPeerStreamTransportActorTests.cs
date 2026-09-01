using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Messages;
using Staffetta.Core.Protocol.Relay;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Transport;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Tests.Protocol.Transport;

[TestClass]
public sealed class BsvPeerStreamTransportActorTests
{
    [TestMethod]
    public async Task CommandQueuedBeforeRunWaitsForHandshakeThenApplies()
    {
        var stream = new ActorDuplexStream(CreateHandshakeFrames());
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var submission = actor.QueueBroadcast(Hash256.DoubleSha256("during-handshake"u8));
        Assert.AreEqual(BsvPeerTransportCommandQueueStatus.Accepted, submission.Status);
        Assert.IsFalse(submission.Application!.IsCompleted);

        var run = actor.RunAsync();

        Assert.AreEqual(
            BsvPeerTransportCommandApplicationKind.PumpApplied,
            (await submission.Application).Kind);
        Assert.AreEqual(1, facts.BecameReadyCount);
        await WaitUntilAsync(() => facts.AnnouncedCount == 1);
        await actor.StopAsync();
        var completion = await run;
        Assert.AreEqual(BsvPeerTransportActorCompletionKind.Stopped, completion.Kind);
    }

    [TestMethod]
    public async Task SilentHandshakeKeepsRelayCommandPendingUntilPeerBecomesReady()
    {
        var stream = new ActorDuplexStream([]);
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var run = actor.RunAsync();
        await WaitUntilAsync(() => stream.PendingReadCount == 1);
        var queued = actor.QueueBroadcast(Hash256.DoubleSha256("pre-ready"u8));

        await Task.Delay(20);
        Assert.IsFalse(queued.Application!.IsCompleted);
        Assert.IsFalse(ReadCommands(stream.WrittenBytes).Contains("inv", StringComparer.Ordinal));

        stream.AppendInput(CreateHandshakeFrames());
        Assert.AreEqual(
            BsvPeerTransportCommandApplicationKind.PumpApplied,
            (await queued.Application).Kind);
        Assert.AreEqual(1, facts.BecameReadyCount);
        await actor.StopAsync();
        await run;
    }

    [TestMethod]
    public async Task SilentReadDoesNotBlockBroadcastOrCancelRead()
    {
        var stream = new ActorDuplexStream(CreateHandshakeFrames());
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var run = actor.RunAsync();
        await WaitUntilAsync(() => facts.BecameReadyCount == 1 && stream.PendingReadCount == 1);
        var cancellationsBefore = stream.ReadCancellationCount;
        var writtenBefore = stream.WrittenByteCount;
        var transactionId = Hash256.DoubleSha256("actor-broadcast"u8);

        var submission = actor.QueueBroadcast(transactionId);

        Assert.AreEqual(BsvPeerTransportCommandQueueStatus.Accepted, submission.Status);
        var application = await submission.Application!;
        Assert.AreEqual(BsvPeerTransportCommandApplicationKind.PumpApplied, application.Kind);
        await WaitUntilAsync(() => facts.AnnouncedCount == 1);
        Assert.IsTrue(stream.WrittenByteCount > writtenBefore);
        Assert.AreEqual(1, stream.PendingReadCount);
        Assert.AreEqual(cancellationsBefore, stream.ReadCancellationCount);

        await actor.StopAsync();
        await run;
    }

    [TestMethod]
    public async Task CompletedReadWinsBeforeQueuedCommandAndIsConsumedOnce()
    {
        var stream = new ActorDuplexStream(CreateHandshakeFrames());
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var run = actor.RunAsync();
        await WaitUntilAsync(() => facts.BecameReadyCount == 1 && stream.PendingReadCount == 1);
        var ping = BsvPeerStreamTransportTestInfrastructure.EncodeBasic(
            "ping"u8,
            [1, 2, 3, 4, 5, 6, 7, 8]);
        stream.AppendInput(ping);
        var transactionId = Hash256.DoubleSha256("read-wins"u8);

        var submission = actor.QueueBroadcast(transactionId);
        Assert.AreEqual(BsvPeerTransportCommandQueueStatus.Accepted, submission.Status);
        Assert.AreEqual(
            BsvPeerTransportCommandApplicationKind.PumpApplied,
            (await submission.Application!).Kind);
        await WaitUntilAsync(() => facts.AnnouncedCount == 1 && stream.PendingReadCount == 1);

        var commands = ReadCommands(stream.WrittenBytes);
        var pongIndex = commands.FindIndex(static command => command == "pong");
        var inventoryIndex = commands.FindIndex(static command => command == "inv");
        Assert.IsTrue(pongIndex >= 0 && inventoryIndex > pongIndex);
        Assert.AreEqual(1, stream.CompletedInjectedReadCount);

        await actor.StopAsync();
        await run;
    }

    [TestMethod]
    public async Task PartialFrameHoldsEightCommandsAndRejectsNinth()
    {
        var stream = new ActorDuplexStream(CreateHandshakeFrames());
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var run = actor.RunAsync();
        await WaitUntilAsync(() => facts.BecameReadyCount == 1 && stream.PendingReadCount == 1);
        stream.AppendInput([BsvPeerStreamTransportTestInfrastructure.NetworkMagic[0]]);
        await WaitUntilAsync(() => stream.PendingReadCount == 1 && stream.CompletedInjectedReadCount == 1);

        var applications = new List<Task<BsvPeerTransportCommandApplication>>();
        for (var index = 0; index < BsvPeerStreamTransportActor.CommandCapacity; index++)
        {
            var transactionId = Hash256.DoubleSha256(BitConverter.GetBytes(index));
            var submission = actor.QueueBroadcast(transactionId);
            Assert.AreEqual(BsvPeerTransportCommandQueueStatus.Accepted, submission.Status);
            applications.Add(submission.Application!);
        }

        var ninth = actor.QueueBroadcast(Hash256.DoubleSha256("ninth"u8));
        Assert.AreEqual(BsvPeerTransportCommandQueueStatus.QueueFull, ninth.Status);
        Assert.IsTrue(applications.All(static application => !application.IsCompleted));

        await actor.StopAsync();
        foreach (var application in applications)
        {
            Assert.AreEqual(
                BsvPeerTransportCommandApplicationKind.Stopped,
                (await application).Kind);
        }

        await run;
        Assert.AreEqual(1, stream.DisposeCount);
    }

    [TestMethod]
    public async Task QueueAcceptanceAndApplicationPrecedeFactAndContinuationsAreAsync()
    {
        var stream = new ActorDuplexStream(CreateHandshakeFrames());
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var run = actor.RunAsync();
        await WaitUntilAsync(() => facts.BecameReadyCount == 1 && stream.PendingReadCount == 1);
        stream.PauseWrites();
        var transactionId = Hash256.DoubleSha256("ordering"u8);

        var submission = actor.QueueBroadcast(transactionId);
        Assert.AreEqual(BsvPeerTransportCommandQueueStatus.Accepted, submission.Status);
        Assert.AreEqual(0, facts.AnnouncedCount);
        var continuation = submission.Application!.ContinueWith(
            _ => actor.QueueFetch(Hash256.DoubleSha256("continuation"u8)),
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        var applied = await submission.Application;
        Assert.AreEqual(BsvPeerTransportCommandApplicationKind.PumpApplied, applied.Kind);
        Assert.AreEqual(0, facts.AnnouncedCount);
        Assert.AreEqual(
            BsvPeerTransportCommandQueueStatus.Accepted,
            (await continuation).Status);
        stream.ResumeWrites();
        await WaitUntilAsync(() => facts.AnnouncedCount == 1);

        await actor.StopAsync();
        await run;
    }

    [TestMethod]
    public async Task StopClosesAdmissionStopsUnappliedCommandsAndDisposesOnce()
    {
        var stream = new ActorDuplexStream(CreateHandshakeFrames());
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var run = actor.RunAsync();
        await WaitUntilAsync(() => facts.BecameReadyCount == 1 && stream.PendingReadCount == 1);
        stream.AppendInput([BsvPeerStreamTransportTestInfrastructure.NetworkMagic[0]]);
        await WaitUntilAsync(() => stream.CompletedInjectedReadCount == 1 && stream.PendingReadCount == 1);
        var queued = actor.QueueFetch(Hash256.DoubleSha256("stopped"u8));

        await actor.StopAsync();

        Assert.AreEqual(
            BsvPeerTransportCommandApplicationKind.Stopped,
            (await queued.Application!).Kind);
        Assert.AreEqual(
            BsvPeerTransportCommandQueueStatus.Stopped,
            actor.QueueFetch(Hash256.DoubleSha256("after-stop"u8)).Status);
        await run;
        Assert.AreEqual(1, stream.DisposeCount);
        Assert.AreEqual(1, stream.ReadCancellationCount);
    }

    [TestMethod]
    public async Task StopBeforeRunCompletesAcceptedCommandAndSharesCleanup()
    {
        var stream = new ActorDuplexStream(CreateHandshakeFrames());
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var queued = actor.QueueBroadcast(Hash256.DoubleSha256("never-run"u8));

        var firstStop = actor.StopAsync().AsTask();
        var secondStop = actor.StopAsync().AsTask();
        await Task.WhenAll(firstStop, secondStop);

        Assert.AreEqual(
            BsvPeerTransportCommandApplicationKind.Stopped,
            (await queued.Application!).Kind);
        Assert.AreEqual(1, stream.DisposeCount);
        Assert.ThrowsException<InvalidOperationException>(() => actor.RunAsync());
    }

    [TestMethod]
    public async Task StopAfterFinalInventoryAckCommitsAndDrainsAnnouncedFact()
    {
        var stream = new ActorDuplexStream(CreateHandshakeFrames());
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var run = actor.RunAsync();
        await WaitUntilAsync(() => facts.BecameReadyCount == 1 && stream.PendingReadCount == 1);
        stream.ResetObservedWrites();
        stream.AfterWriteOrdinal = 2;
        stream.AfterWriteAsync = async () =>
        {
            stream.AfterWriteAsync = null;
            await actor.StopAsync();
        };

        var queued = actor.QueueBroadcast(Hash256.DoubleSha256("ack-stop"u8));
        Assert.AreEqual(
            BsvPeerTransportCommandApplicationKind.PumpApplied,
            (await queued.Application!).Kind);
        await run;

        Assert.AreEqual(1, facts.AnnouncedCount);
        Assert.AreEqual(2, stream.ObservedWriteCount);
        Assert.AreEqual(MessageHeaderCodec.BasicHeaderLength, stream.GetObservedWriteLength(1));
        Assert.AreEqual(1 + InventoryVectorCodec.EncodedLength, stream.GetObservedWriteLength(2));
        Assert.AreEqual(1, stream.DisposeCount);
    }

    [TestMethod]
    public async Task StopAfterInventoryHeaderDoesNotInventAnnouncedFact()
    {
        var stream = new ActorDuplexStream(CreateHandshakeFrames());
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var run = actor.RunAsync();
        await WaitUntilAsync(() => facts.BecameReadyCount == 1 && stream.PendingReadCount == 1);
        stream.ResetObservedWrites();
        stream.AfterWriteOrdinal = 1;
        stream.AfterWriteAsync = async () =>
        {
            stream.AfterWriteAsync = null;
            await actor.StopAsync();
        };

        var queued = actor.QueueBroadcast(Hash256.DoubleSha256("header-stop"u8));
        Assert.AreEqual(
            BsvPeerTransportCommandApplicationKind.PumpApplied,
            (await queued.Application!).Kind);
        await run;

        Assert.AreEqual(0, facts.AnnouncedCount);
        Assert.AreEqual(1, stream.ObservedWriteCount);
        Assert.AreEqual(MessageHeaderCodec.BasicHeaderLength, stream.GetObservedWriteLength(1));
        Assert.AreEqual(1, stream.DisposeCount);
    }

    [TestMethod]
    public async Task FactSinkMayAwaitStopWithoutActorSelfDeadlock()
    {
        var stream = new ActorDuplexStream(CreateHandshakeFrames());
        var facts = new StopOnAnnouncedFactSink();
        await using var actor = CreateActor(stream, facts);
        facts.Actor = actor;
        var run = actor.RunAsync();
        await WaitUntilAsync(() => facts.BecameReadyCount == 1 && stream.PendingReadCount == 1);

        var queued = actor.QueueBroadcast(Hash256.DoubleSha256("fact-stop"u8));
        Assert.AreEqual(
            BsvPeerTransportCommandApplicationKind.PumpApplied,
            (await queued.Application!).Kind);
        await run.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreEqual(1, facts.AnnouncedCount);
        Assert.AreEqual(1, stream.DisposeCount);
    }

    [TestMethod]
    public async Task SynchronousFirstWriteCallbackMayAwaitStopAgainstPublishedRunTask()
    {
        var stream = new ActorDuplexStream([]);
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var callbackCompleted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        stream.ResetObservedWrites();
        stream.AfterWriteOrdinal = 1;
        stream.AfterWriteAsync = async () =>
        {
            await actor.StopAsync();
            callbackCompleted.TrySetResult();
        };

        var run = actor.RunAsync();
        await callbackCompleted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await run.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreEqual(MessageHeaderCodec.BasicHeaderLength, stream.GetObservedWriteLength(1));
        Assert.AreEqual(1, stream.DisposeCount);
    }

    [TestMethod]
    public async Task ReadOperationRejectsDoubleApply()
    {
        await using var fixture = await CreateReadyPumpAsync();
        fixture.Stream.AppendInput([0xe3]);
        var read = fixture.Pump.BeginPeerRead(CancellationToken.None);
        Assert.AreEqual(
            BsvPeerTransportStepKind.Progress,
            (await fixture.Pump.ApplyPeerReadAsync(read, CancellationToken.None)).Kind);

        await Assert.ThrowsExceptionAsync<InvalidOperationException>(async () =>
            await fixture.Pump.ApplyPeerReadAsync(read, CancellationToken.None));
    }

    [TestMethod]
    public async Task ReadOperationRejectsStaleRevisionEvenWhenCompletionTaskMayBeCached()
    {
        await using var fixture = await CreateReadyPumpAsync();
        fixture.Stream.AppendInput([0xe3]);
        var first = fixture.Pump.BeginPeerRead(CancellationToken.None);
        Assert.AreEqual(
            BsvPeerTransportStepKind.Progress,
            (await fixture.Pump.ApplyPeerReadAsync(first, CancellationToken.None)).Kind);
        Assert.AreEqual(
            BsvPeerTransportDriveKind.Progress,
            (await fixture.Pump.StepLocalAsync()).Kind);
        fixture.Stream.AppendInput([0xe1]);
        var second = fixture.Pump.BeginPeerRead(CancellationToken.None);
        Assert.IsTrue(ReferenceEquals(first.Completion, second.Completion));

        await Assert.ThrowsExceptionAsync<InvalidOperationException>(async () =>
            await fixture.Pump.ApplyPeerReadAsync(first, CancellationToken.None));
        Assert.AreEqual(
            BsvPeerTransportStepKind.Progress,
            (await fixture.Pump.ApplyPeerReadAsync(second, CancellationToken.None)).Kind);
    }

    [TestMethod]
    public async Task ReadOperationRejectsCrossPumpAuthority()
    {
        await using var firstFixture = await CreateReadyPumpAsync();
        await using var secondFixture = await CreateReadyPumpAsync();
        firstFixture.Stream.AppendInput([0xe3]);
        secondFixture.Stream.AppendInput([0xe3]);
        var first = firstFixture.Pump.BeginPeerRead(CancellationToken.None);
        var second = secondFixture.Pump.BeginPeerRead(CancellationToken.None);
        Assert.IsTrue(ReferenceEquals(first.Completion, second.Completion));

        await Assert.ThrowsExceptionAsync<InvalidOperationException>(async () =>
            await secondFixture.Pump.ApplyPeerReadAsync(first, CancellationToken.None));
        Assert.AreEqual(
            BsvPeerTransportStepKind.Progress,
            (await firstFixture.Pump.ApplyPeerReadAsync(first, CancellationToken.None)).Kind);
        Assert.AreEqual(
            BsvPeerTransportStepKind.Progress,
            (await secondFixture.Pump.ApplyPeerReadAsync(second, CancellationToken.None)).Kind);
    }

    [TestMethod]
    public async Task CleanPeerEndPreservesPeerClosedCompletion()
    {
        var stream = new ActorDuplexStream(CreateHandshakeFrames());
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var run = actor.RunAsync();
        await WaitUntilAsync(() => facts.BecameReadyCount == 1 && stream.PendingReadCount == 1);

        stream.CompletePendingReadAsPeerEnd();
        var completion = await run;

        Assert.AreEqual(BsvPeerTransportActorCompletionKind.TransportTerminal, completion.Kind);
        Assert.AreEqual(BsvPeerTransportStepKind.PeerClosed, completion.TransportResult.Kind);
        Assert.AreEqual(
            BsvPeerTransportTerminalReason.PeerClosed,
            completion.TransportResult.Reason);
    }

    [TestMethod]
    public async Task PeerReadFailurePreservesTransportReadFailureCompletion()
    {
        var stream = new ActorDuplexStream(CreateHandshakeFrames());
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var run = actor.RunAsync();
        await WaitUntilAsync(() => facts.BecameReadyCount == 1 && stream.PendingReadCount == 1);

        stream.FailPendingRead(new IOException("Injected actor read failure."));
        var completion = await run;

        Assert.AreEqual(BsvPeerTransportActorCompletionKind.TransportTerminal, completion.Kind);
        Assert.AreEqual(BsvPeerTransportStepKind.Faulted, completion.TransportResult.Kind);
        Assert.AreEqual(
            BsvPeerTransportTerminalReason.TransportReadFailure,
            completion.TransportResult.Reason);
    }

    [TestMethod]
    public async Task StopRaceWithPeerEndPreservesPeerClosedTerminal()
    {
        var stream = new ActorDuplexStream(CreateHandshakeFrames())
        {
            IgnoreReadCancellation = true,
        };
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var run = actor.RunAsync();
        await WaitUntilAsync(() => facts.BecameReadyCount == 1 && stream.PendingReadCount == 1);

        var stop = actor.StopAsync().AsTask();
        await stream.CancellationObserved.WaitAsync(TimeSpan.FromSeconds(5));
        stream.CompletePendingReadAsPeerEnd();
        var completion = await run;
        await stop;

        Assert.AreEqual(BsvPeerTransportActorCompletionKind.TransportTerminal, completion.Kind);
        Assert.AreEqual(BsvPeerTransportStepKind.PeerClosed, completion.TransportResult.Kind);
        Assert.AreEqual(
            BsvPeerTransportTerminalReason.PeerClosed,
            completion.TransportResult.Reason);
    }

    [TestMethod]
    public async Task StopRaceWithReadFaultPreservesTransportReadFailureTerminal()
    {
        var stream = new ActorDuplexStream(CreateHandshakeFrames())
        {
            IgnoreReadCancellation = true,
        };
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var run = actor.RunAsync();
        await WaitUntilAsync(() => facts.BecameReadyCount == 1 && stream.PendingReadCount == 1);

        var stop = actor.StopAsync().AsTask();
        await stream.CancellationObserved.WaitAsync(TimeSpan.FromSeconds(5));
        stream.FailPendingRead(new IOException("Injected stop-race read failure."));
        var completion = await run;
        await stop;

        Assert.AreEqual(BsvPeerTransportActorCompletionKind.TransportTerminal, completion.Kind);
        Assert.AreEqual(BsvPeerTransportStepKind.Faulted, completion.TransportResult.Kind);
        Assert.AreEqual(
            BsvPeerTransportTerminalReason.TransportReadFailure,
            completion.TransportResult.Reason);
    }

    [TestMethod]
    public async Task StopDuringPausedWriteCompletesStoppedWithoutAnnouncedFact()
    {
        var stream = new ActorDuplexStream(CreateHandshakeFrames());
        var facts = new CountingFactSink();
        await using var actor = CreateActor(stream, facts);
        var run = actor.RunAsync();
        await WaitUntilAsync(() => facts.BecameReadyCount == 1 && stream.PendingReadCount == 1);
        stream.ResetObservedWrites();
        stream.PauseWrites();
        var queued = actor.QueueBroadcast(Hash256.DoubleSha256("paused-write-stop"u8));
        Assert.AreEqual(
            BsvPeerTransportCommandApplicationKind.PumpApplied,
            (await queued.Application!).Kind);
        await WaitUntilAsync(() => stream.WriteStartedCount == 1);

        await actor.StopAsync();
        var completion = await run;

        Assert.AreEqual(BsvPeerTransportActorCompletionKind.Stopped, completion.Kind);
        Assert.AreEqual(0, facts.AnnouncedCount);
        Assert.AreEqual(0, stream.ObservedWriteCount);
        Assert.AreEqual(1, stream.DisposeCount);
    }

    [TestMethod]
    public async Task StopDuringTransactionSourceReadCompletesStoppedWithoutSentFactOrRetry()
    {
        var transactionId = Hash256.DoubleSha256("blocking-source"u8);
        var source = new BlockingPayloadSource(transactionId, length: 1);
        var stream = new ActorDuplexStream(CreateHandshakeFrames());
        var facts = new CountingFactSink();
        await using var actor = CreateActor(
            stream,
            facts,
            new BufferPayloadSourceProvider(source));
        var run = actor.RunAsync();
        await WaitUntilAsync(() => facts.BecameReadyCount == 1 && stream.PendingReadCount == 1);
        var queued = actor.QueueBroadcast(transactionId);
        Assert.AreEqual(
            BsvPeerTransportCommandApplicationKind.PumpApplied,
            (await queued.Application!).Kind);
        await WaitUntilAsync(() => facts.AnnouncedCount == 1 && stream.PendingReadCount == 1);
        stream.AppendInput(
            BsvPeerStreamTransportTestInfrastructure.EncodeInventory("getdata"u8, transactionId));
        await source.ReadStarted.WaitAsync(TimeSpan.FromSeconds(5));

        await actor.StopAsync();
        var completion = await run;

        Assert.AreEqual(BsvPeerTransportActorCompletionKind.Stopped, completion.Kind);
        Assert.AreEqual(0, facts.SentToPeerCount);
        Assert.AreEqual(1, source.ReadCount);
        Assert.AreEqual(1, source.DisposeCount);
        Assert.AreEqual(1, stream.DisposeCount);
    }

    private static BsvPeerStreamTransportActor CreateActor(
        ActorDuplexStream stream,
        IBsvPeerSessionFactSink facts,
        IBsvTransactionPayloadSourceProvider? transactionSources = null)
    {
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [192, 0, 2, 1], 8333, out var receiving));
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [192, 0, 2, 2], 8333, out var source));
        var local = new BsvPeerLocalHandshakeConfiguration(
            BsvPeerStreamTransportTestInfrastructure.MinimumProtocolVersion,
            services: 1,
            timestampUnixSeconds: 1_788_131_200,
            receiving,
            source,
            nonce: 0x0102_0304_0506_0708,
            "/Staffetta:actor-test/"u8,
            startHeight: 948_321,
            relay: true,
            maximumReceivePayloadLength:
                (uint)BsvPeerStreamTransportTestInfrastructure.MaximumPayloadLength,
            "Default"u8,
            includeStreamPolicies: true);
        return new BsvPeerStreamTransportActor(
            stream,
            BsvPeerStreamTransportTestInfrastructure.NetworkMagic,
            BsvPeerStreamTransportTestInfrastructure.MaximumPayloadLength,
            BsvPeerStreamTransportTestInfrastructure.MinimumProtocolVersion,
            local,
            new NoOpTransactionSink(),
            transactionSources ?? new BufferPayloadSourceProvider(
                new CountingPayloadSource(default, 0, [])),
            facts,
            new BsvPeerStreamTransportOptions(
                readBufferLength: 1024,
                transactionBufferLength: 1024,
                maximumWriteLength: 1024,
                leaveOpen: false));
    }

    private static ValueTask<TransportFixture> CreateReadyPumpAsync() =>
        BsvPeerStreamTransportTestInfrastructure.CreateReadyAsync(
            new BufferPayloadSourceProvider(new CountingPayloadSource(default, 0, [])));

    private static byte[] CreateHandshakeFrames() =>
        BsvPeerStreamTransportTestInfrastructure.Concatenate(
            BsvPeerStreamTransportTestInfrastructure.Concatenate(
                BsvPeerStreamTransportTestInfrastructure.EncodeBasic(
                    "version"u8,
                    BsvPeerStreamTransportTestInfrastructure.CreateVersionPayload()),
                BsvPeerStreamTransportTestInfrastructure.EncodeBasic("verack"u8, [])),
            BsvPeerStreamTransportTestInfrastructure.EncodeBasic(
                "protoconf"u8,
                BsvPeerStreamTransportTestInfrastructure.CreateProtoconfPayload(
                    (uint)BsvPeerStreamTransportTestInfrastructure.MaximumPayloadLength)));

    private static async Task WaitUntilAsync(Func<bool> predicate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!predicate() && !timeout.IsCancellationRequested)
        {
            await Task.Delay(1, timeout.Token).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        }

        Assert.IsTrue(predicate(), "Actor did not reach the expected state.");
    }

    private static List<string> ReadCommands(IReadOnlyList<byte> bytes)
    {
        var result = new List<string>();
        var offset = 0;
        var commandBytes = new byte[MessageCommand.MaximumLength];
        while (offset < bytes.Count)
        {
            var headerBytes = new byte[MessageHeaderCodec.ExtendedHeaderLength];
            var available = Math.Min(headerBytes.Length, bytes.Count - offset);
            for (var index = 0; index < available; index++)
            {
                headerBytes[index] = bytes[offset + index];
            }

            Assert.AreEqual(
                OperationStatus.Done,
                MessageHeaderCodec.TryParse(
                    headerBytes.AsSpan(0, available),
                    BsvPeerStreamTransportTestInfrastructure.NetworkMagic,
                    BsvPeerStreamTransportTestInfrastructure.MaximumPayloadLength,
                    out var header,
                    out var consumed));
            Assert.AreEqual(
                OperationStatus.Done,
                header.Command.TryCopyTo(commandBytes, out var commandLength));
            result.Add(System.Text.Encoding.ASCII.GetString(commandBytes.AsSpan(0, commandLength)));
            offset += consumed + checked((int)header.PayloadLength);
        }

        return result;
    }
}

internal sealed class StopOnAnnouncedFactSink : IBsvPeerSessionFactSink
{
    internal BsvPeerStreamTransportActor? Actor { get; set; }

    internal int BecameReadyCount { get; private set; }

    internal int AnnouncedCount { get; private set; }

    public ValueTask OnHandshakeFactAsync(
        BsvHandshakeOutput output,
        CancellationToken cancellationToken)
    {
        if (output.Kind == BsvHandshakeOutputKind.BecameReady)
        {
            BecameReadyCount++;
        }

        return ValueTask.CompletedTask;
    }

    public async ValueTask OnBroadcastFactAsync(
        BsvTransactionBroadcastOutput output,
        CancellationToken cancellationToken)
    {
        if (output.Kind == BsvTransactionBroadcastOutputKind.Announced)
        {
            AnnouncedCount++;
            await Actor!.StopAsync();
        }
    }

    public ValueTask OnFetchFactAsync(
        BsvTransactionFetchOutput output,
        CancellationToken cancellationToken) => ValueTask.CompletedTask;
}

internal sealed class BlockingPayloadSource : IBsvTransactionPayloadSource
{
    private readonly TaskCompletionSource _readStarted =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal BlockingPayloadSource(Hash256 transactionId, ulong length)
    {
        TransactionId = transactionId;
        Length = length;
    }

    public Hash256 TransactionId { get; }

    public ulong Length { get; }

    internal Task ReadStarted => _readStarted.Task;

    internal int ReadCount { get; private set; }

    internal int DisposeCount { get; private set; }

    public async ValueTask<int> ReadAsync(
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        ReadCount++;
        _readStarted.TrySetResult();
        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        return 0;
    }

    public ValueTask DisposeAsync()
    {
        DisposeCount++;
        return ValueTask.CompletedTask;
    }
}

internal sealed class ActorDuplexStream : Stream
{
    private readonly object _gate = new();
    private readonly Queue<byte> _input = new();
    private readonly List<byte> _written = [];
    private PendingRead? _pendingRead;
    private TaskCompletionSource? _writeGate;
    private bool _disposed;

    internal ActorDuplexStream(byte[] input)
    {
        AppendInput(input);
    }

    internal IReadOnlyList<byte> WrittenBytes => _written;

    internal long WrittenByteCount => _written.Count;

    private int _pendingReadCount;
    private int _completedInjectedReadCount;
    private int _readCancellationCount;
    private int _disposeCount;
    private int _observedWriteCount;
    private int _writeStartedCount;
    private readonly int[] _observedWriteLengths = new int[8];
    private readonly TaskCompletionSource _cancellationObserved =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal int PendingReadCount => Volatile.Read(ref _pendingReadCount);

    internal int CompletedInjectedReadCount => Volatile.Read(ref _completedInjectedReadCount);

    internal int ReadCancellationCount => Volatile.Read(ref _readCancellationCount);

    internal int DisposeCount => Volatile.Read(ref _disposeCount);

    internal bool IgnoreReadCancellation { get; set; }

    internal Task CancellationObserved => _cancellationObserved.Task;

    internal Func<ValueTask>? AfterWriteAsync { get; set; }

    internal int AfterWriteOrdinal { get; set; } = 1;

    internal int ObservedWriteCount => Volatile.Read(ref _observedWriteCount);

    internal int WriteStartedCount => Volatile.Read(ref _writeStartedCount);

    internal void ResetObservedWrites()
    {
        Array.Clear(_observedWriteLengths);
        Volatile.Write(ref _observedWriteCount, 0);
        Volatile.Write(ref _writeStartedCount, 0);
    }

    internal int GetObservedWriteLength(int ordinal) =>
        Volatile.Read(ref _observedWriteLengths[ordinal - 1]);

    internal void PauseWrites() =>
        _writeGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

    internal void ResumeWrites() => _writeGate?.TrySetResult();

    internal void AppendInput(byte[] bytes)
    {
        PendingRead? completion = null;
        lock (_gate)
        {
            foreach (var value in bytes)
            {
                _input.Enqueue(value);
            }

            if (_pendingRead is not null)
            {
                completion = _pendingRead;
                _pendingRead = null;
                _pendingReadCount--;
                CompleteRead(completion);
                _completedInjectedReadCount++;
            }
        }

        completion?.Registration.Dispose();
    }

    internal void CompletePendingReadAsPeerEnd() => CompletePendingRead(0, null);

    internal void FailPendingRead(Exception exception) => CompletePendingRead(0, exception);

    public override ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_input.Count != 0)
            {
                return ValueTask.FromResult(CopyInput(buffer.Span));
            }

            if (_pendingRead is not null)
            {
                throw new InvalidOperationException("Only one read is supported.");
            }

            var pending = new PendingRead(buffer);
            _pendingRead = pending;
            _pendingReadCount++;
            pending.Registration = cancellationToken.Register(
                static state => ((ActorDuplexStream)state!).CancelPendingRead(),
                this);
            return new ValueTask<int>(pending.Completion.Task);
        }
    }

    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Interlocked.Increment(ref _writeStartedCount);
        if (_writeGate is { } gate)
        {
            await gate.Task.WaitAsync(cancellationToken);
        }

        lock (_gate)
        {
            foreach (var value in buffer.Span)
            {
                _written.Add(value);
            }
        }

        var writeOrdinal = Interlocked.Increment(ref _observedWriteCount);
        if (writeOrdinal <= _observedWriteLengths.Length)
        {
            Volatile.Write(ref _observedWriteLengths[writeOrdinal - 1], buffer.Length);
        }

        if (AfterWriteAsync is { } callback && writeOrdinal == AfterWriteOrdinal)
        {
            await callback();
        }

    }

    public override async ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (!_disposed)
            {
                _disposed = true;
                _disposeCount++;
            }
        }

        await base.DisposeAsync();
    }

    private void CancelPendingRead()
    {
        PendingRead? pending;
        lock (_gate)
        {
            pending = _pendingRead;
            if (pending is null)
            {
                return;
            }

            _readCancellationCount++;
            _cancellationObserved.TrySetResult();
            if (IgnoreReadCancellation)
            {
                return;
            }

            _pendingRead = null;
            _pendingReadCount--;
        }

        pending.Completion.TrySetCanceled();
    }

    private void CompletePendingRead(int result, Exception? exception)
    {
        PendingRead pending;
        lock (_gate)
        {
            pending = _pendingRead ?? throw new InvalidOperationException("No read is pending.");
            _pendingRead = null;
            _pendingReadCount--;
        }

        if (exception is null)
        {
            pending.Completion.TrySetResult(result);
        }
        else
        {
            pending.Completion.TrySetException(exception);
        }

        pending.Registration.Dispose();
    }

    private void CompleteRead(PendingRead pending) =>
        pending.Completion.TrySetResult(CopyInput(pending.Buffer.Span));

    private int CopyInput(Span<byte> destination)
    {
        var length = Math.Min(destination.Length, _input.Count);
        for (var index = 0; index < length; index++)
        {
            destination[index] = _input.Dequeue();
        }

        return length;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => throw new NotSupportedException();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    private sealed class PendingRead(Memory<byte> buffer)
    {
        internal Memory<byte> Buffer { get; } = buffer;
        internal TaskCompletionSource<int> Completion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal CancellationTokenRegistration Registration { get; set; }
    }
}
