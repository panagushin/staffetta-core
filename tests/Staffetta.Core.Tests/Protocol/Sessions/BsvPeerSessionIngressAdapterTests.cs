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
public sealed class BsvPeerSessionIngressAdapterTests
{
    private const int MinimumProtocolVersion = VersionPayloadCodec.CurrentProtocolVersion;
    private const ulong LocalNonce = 0x0102_0304_0506_0708;
    private const ulong PeerNonce = 0x1112_1314_1516_1718;
    private const ulong MaximumPayloadLength = 4 * 1024 * 1024;

    private static readonly byte[] NetworkMagic = [0xe3, 0xe1, 0xf3, 0xe8];

    [TestMethod]
    public void FakePeerBroadcastFlowKeepsWriteIntentsAndFactsSeparate()
    {
        var sink = new RecordingTransactionSink();
        using var session = CreateReadySession(sink, bytewise: true);
        var transaction = CreateMinimalTransaction();
        var transactionId = Hash256.DoubleSha256(transaction);
        Span<BsvTransactionBroadcastOutput> outputs =
            stackalloc BsvTransactionBroadcastOutput[BsvTransactionBroadcastStateMachine.MaximumOutputCount];

        Assert.AreEqual(OperationStatus.Done, session.StartBroadcast(transactionId));
        Assert.IsFalse(session.IsAnnounced);
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            session.Consume(EncodeInventory("getdata"u8, transactionId), out var blockedConsumed));
        Assert.AreEqual(0, blockedConsumed);
        DrainBroadcast(session, outputs, BsvTransactionBroadcastOutputKind.SendInventory, transactionId);
        Assert.IsFalse(session.IsAnnounced);

        Assert.AreEqual(OperationStatus.Done, CommitInventoryEgress(session, transactionId));
        DrainBroadcast(session, outputs, BsvTransactionBroadcastOutputKind.Announced, transactionId);
        Assert.IsTrue(session.IsAnnounced);

        ConsumeFrame(session, EncodeInventory("getdata"u8, transactionId), bytewise: true);
        Assert.AreEqual(OperationStatus.Done, session.DrainBroadcastOutputs(outputs, out var requestedWritten));
        Assert.AreEqual(2, requestedWritten);
        Assert.AreEqual(BsvTransactionBroadcastOutputKind.RequestedByPeer, outputs[0].Kind);
        Assert.AreEqual(BsvTransactionBroadcastOutputKind.SendTransaction, outputs[1].Kind);
        Assert.IsTrue(session.WasRequestedByPeer);
        Assert.IsFalse(session.IsSentToPeer);

        Assert.AreEqual(
            OperationStatus.Done,
            CommitTransactionEgress(session, transaction, transactionId));
        DrainBroadcast(session, outputs, BsvTransactionBroadcastOutputKind.SentToPeer, transactionId);
        Assert.IsTrue(session.IsSentToPeer);

        ConsumeFrame(session, EncodeInventory("inv"u8, transactionId), bytewise: true);
        DrainBroadcast(session, outputs, BsvTransactionBroadcastOutputKind.ObservedFromPeer, transactionId);
        Assert.IsTrue(session.WasObservedFromPeer);
        Assert.AreEqual(BsvTransactionBroadcastState.SentToPeer, session.BroadcastState);
        Assert.AreEqual(0, sink.CommittedCount);
    }

    [TestMethod]
    public void ValidatedTransactionUsesTheExactFrameDigestAndLength()
    {
        var sink = new RecordingTransactionSink();
        using var session = CreateReadySession(sink, bytewise: false);
        var transaction = CreateMinimalTransaction();

        ConsumeFrame(session, EncodeBasic("tx"u8, transaction), bytewise: true);

        Assert.AreEqual(1, sink.CommittedCount);
        Assert.AreEqual(0, sink.AbortedCount);
        Assert.AreEqual(Hash256.DoubleSha256(transaction), sink.LastSummary.TransactionId);
        Assert.AreEqual((ulong)transaction.Length, sink.LastSummary.SerializedLength);
    }

    [TestMethod]
    public void FetchIntentBecomesRequestedOnlyAfterWriteCommitThenReceivesTransaction()
    {
        var sink = new RecordingTransactionSink();
        using var session = CreateReadySession(sink, bytewise: false);
        var transaction = CreateMinimalTransaction();
        var transactionId = Hash256.DoubleSha256(transaction);
        Span<BsvTransactionFetchOutput> outputs =
            stackalloc BsvTransactionFetchOutput[BsvTransactionFetchStateMachine.MaximumOutputCount];

        Assert.AreEqual(OperationStatus.Done, session.StartFetch(transactionId));
        Assert.AreEqual(BsvTransactionFetchState.AwaitingInventory, session.FetchState);
        ConsumeFrame(session, EncodeInventory("inv"u8, transactionId), bytewise: true);
        Assert.AreEqual(BsvTransactionFetchState.GetDataWritePending, session.FetchState);
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            session.Consume(EncodeBasic("tx"u8, transaction), out var blockedConsumed));
        Assert.AreEqual(0, blockedConsumed);
        DrainFetch(session, outputs, BsvTransactionFetchOutputKind.SendGetData, transactionId);
        Assert.AreEqual(BsvTransactionFetchState.GetDataWritePending, session.FetchState);

        Assert.AreEqual(OperationStatus.Done, CommitGetDataEgress(session, transactionId));
        DrainFetch(session, outputs, BsvTransactionFetchOutputKind.Requested, transactionId);
        Assert.AreEqual(BsvTransactionFetchState.Requested, session.FetchState);

        ConsumeFrame(session, EncodeBasic("tx"u8, transaction), bytewise: true);
        Assert.AreEqual(1, sink.CommittedCount);
        Assert.AreEqual(transactionId, sink.LastSummary.TransactionId);
        DrainFetch(session, outputs, BsvTransactionFetchOutputKind.Received, transactionId);
        Assert.AreEqual(BsvTransactionFetchState.Received, session.FetchState);
    }

    [TestMethod]
    public void NotFoundBeforeGetDataCommitIsDeferredAndWrongVectorsAreIgnored()
    {
        var sink = new RecordingTransactionSink();
        using var session = CreateReadySession(sink, bytewise: false);
        var transactionId = Hash256.DoubleSha256(CreateMinimalTransaction());
        var otherId = Hash256.DoubleSha256([0x42]);
        Span<BsvTransactionFetchOutput> outputs =
            stackalloc BsvTransactionFetchOutput[BsvTransactionFetchStateMachine.MaximumOutputCount];
        Assert.AreEqual(OperationStatus.Done, session.StartFetch(transactionId));

        ConsumeFrame(session, EncodeInventory("inv"u8, transactionId, type: 2), bytewise: false);
        ConsumeFrame(session, EncodeInventory("inv"u8, otherId), bytewise: false);
        Assert.AreEqual(BsvTransactionFetchState.AwaitingInventory, session.FetchState);
        Assert.AreEqual(0, session.PendingFetchOutputCount);

        ConsumeFrame(session, EncodeInventory("inv"u8, transactionId), bytewise: false);
        DrainFetch(session, outputs, BsvTransactionFetchOutputKind.SendGetData, transactionId);
        ConsumeFrame(session, EncodeInventory("notfound"u8, transactionId, type: 2), bytewise: false);
        ConsumeFrame(session, EncodeInventory("notfound"u8, otherId), bytewise: false);
        ConsumeFrame(session, EncodeInventory("notfound"u8, transactionId), bytewise: false);
        Assert.AreEqual(0, session.PendingFetchOutputCount);
        Assert.AreEqual(BsvTransactionFetchState.GetDataWritePending, session.FetchState);
        Assert.AreEqual(OperationStatus.Done, CommitGetDataEgress(session, transactionId));
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            session.DrainFetchOutputs(outputs[..1], out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.AreEqual(2, session.PendingFetchOutputCount);
        Assert.AreEqual(OperationStatus.Done, session.DrainFetchOutputs(outputs, out var written));
        Assert.AreEqual(2, written);
        Assert.AreEqual(BsvTransactionFetchOutputKind.Requested, outputs[0].Kind);
        Assert.AreEqual(BsvTransactionFetchOutputKind.NotFound, outputs[1].Kind);
        Assert.AreEqual(BsvTransactionFetchState.NotFound, session.FetchState);
        Assert.AreEqual(OperationStatus.InvalidData, session.CommitEgressCompletion());
        Assert.AreEqual(0, session.PendingFetchOutputCount);
    }

    [TestMethod]
    public void UnexpectedTransactionIsCommittedAsObservationAndLeavesFetchArmed()
    {
        var sink = new RecordingTransactionSink();
        using var session = CreateReadySession(sink, bytewise: false);
        var targetId = Hash256.DoubleSha256([0x11]);
        var transaction = CreateMinimalTransaction();
        var observedId = Hash256.DoubleSha256(transaction);
        Span<BsvTransactionFetchOutput> outputs =
            stackalloc BsvTransactionFetchOutput[BsvTransactionFetchStateMachine.MaximumOutputCount];
        Assert.AreEqual(OperationStatus.Done, session.StartFetch(targetId));

        ConsumeFrame(session, EncodeBasic("tx"u8, transaction), bytewise: false);

        Assert.AreEqual(1, sink.CommittedCount);
        Assert.AreEqual(observedId, sink.LastSummary.TransactionId);
        DrainFetch(session, outputs, BsvTransactionFetchOutputKind.UnexpectedTransaction, observedId);
        Assert.AreEqual(BsvTransactionFetchState.AwaitingInventory, session.FetchState);
    }

    [TestMethod]
    public void OneInventoryPreservesSimultaneousBroadcastAndFetchOutputs()
    {
        var sink = new RecordingTransactionSink();
        using var session = CreateReadySession(sink, bytewise: false);
        var transactionId = Hash256.DoubleSha256(CreateMinimalTransaction());
        Span<BsvTransactionBroadcastOutput> broadcastOutputs =
            stackalloc BsvTransactionBroadcastOutput[BsvTransactionBroadcastStateMachine.MaximumOutputCount];
        Span<BsvTransactionFetchOutput> fetchOutputs =
            stackalloc BsvTransactionFetchOutput[BsvTransactionFetchStateMachine.MaximumOutputCount];
        Assert.AreEqual(OperationStatus.Done, session.StartBroadcast(transactionId));
        DrainBroadcast(
            session,
            broadcastOutputs,
            BsvTransactionBroadcastOutputKind.SendInventory,
            transactionId);
        Assert.AreEqual(OperationStatus.Done, CommitInventoryEgress(session, transactionId));
        DrainBroadcast(
            session,
            broadcastOutputs,
            BsvTransactionBroadcastOutputKind.Announced,
            transactionId);
        Assert.AreEqual(OperationStatus.Done, session.StartFetch(transactionId));

        ConsumeFrame(session, EncodeInventory("inv"u8, transactionId), bytewise: false);

        Assert.AreEqual(1, session.PendingBroadcastOutputCount);
        Assert.AreEqual(1, session.PendingFetchOutputCount);
        DrainBroadcast(
            session,
            broadcastOutputs,
            BsvTransactionBroadcastOutputKind.ObservedFromPeer,
            transactionId);
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            session.Consume([], out var blockedConsumed));
        Assert.AreEqual(0, blockedConsumed);
        DrainFetch(session, fetchOutputs, BsvTransactionFetchOutputKind.SendGetData, transactionId);
    }

    [TestMethod]
    public void BadInventoryChecksumPublishesNoObservationAndFaultsTheSession()
    {
        var sink = new RecordingTransactionSink();
        using var session = CreateReadySession(sink, bytewise: false);
        var transactionId = Hash256.DoubleSha256(CreateMinimalTransaction());
        Span<BsvTransactionBroadcastOutput> outputs =
            stackalloc BsvTransactionBroadcastOutput[BsvTransactionBroadcastStateMachine.MaximumOutputCount];
        Assert.AreEqual(OperationStatus.Done, session.StartBroadcast(transactionId));
        Assert.AreEqual(OperationStatus.Done, session.DrainBroadcastOutputs(outputs, out _));
        Assert.AreEqual(OperationStatus.Done, CommitInventoryEgress(session, transactionId));
        Assert.AreEqual(OperationStatus.Done, session.DrainBroadcastOutputs(outputs, out _));
        Assert.AreEqual(OperationStatus.Done, session.StartFetch(transactionId));
        var frame = EncodeInventory("inv"u8, transactionId);
        frame[^1] ^= 0xff;

        Assert.AreEqual(OperationStatus.InvalidData, session.Consume(frame, out var consumed));
        Assert.AreEqual(frame.Length, consumed);
        Assert.IsFalse(session.WasObservedFromPeer);
        Assert.AreEqual(0, session.PendingBroadcastOutputCount);
        Assert.AreEqual(BsvTransactionBroadcastState.Terminal, session.BroadcastState);
        Assert.AreEqual(
            BsvTransactionBroadcastTerminalReason.WireViolation,
            session.BroadcastTerminalReason);
        Assert.AreEqual(BsvTransactionFetchState.Terminal, session.FetchState);
        Assert.AreEqual(BsvTransactionFetchTerminalReason.WireViolation, session.FetchTerminalReason);
        Assert.AreEqual(0, session.PendingFetchOutputCount);
        Assert.AreEqual(OperationStatus.InvalidData, session.Consume([], out consumed));
        Assert.AreEqual(0, consumed);
    }

    [TestMethod]
    public void TransactionWithTrailingFrameBytesAbortsWithoutCommit()
    {
        var sink = new RecordingTransactionSink();
        using var session = CreateReadySession(sink, bytewise: false);
        var transaction = CreateMinimalTransaction();
        var payload = new byte[transaction.Length + 1];
        transaction.CopyTo(payload, 0);
        payload[^1] = 0x42;
        var frame = EncodeBasic("tx"u8, payload);
        Assert.AreEqual(OperationStatus.Done, session.StartFetch(Hash256.DoubleSha256(transaction)));

        Assert.AreEqual(OperationStatus.InvalidData, session.Consume(frame, out var consumed));
        Assert.AreEqual(frame.Length, consumed);
        Assert.AreEqual(0, sink.CommittedCount);
        Assert.AreEqual(1, sink.AbortedCount);
        Assert.AreEqual(BsvTransactionFetchState.Terminal, session.FetchState);
        Assert.AreEqual(BsvTransactionFetchTerminalReason.WireViolation, session.FetchTerminalReason);
    }

    [TestMethod]
    public void CaughtTransactionSinkReentryStillFaultsBeforeLaterCallbacksOrCommit()
    {
        var sink = new ReenteringTransactionSink();
        using var session = new BsvPeerSessionIngressAdapter(
            NetworkMagic,
            MaximumPayloadLength,
            MinimumProtocolVersion,
            sink);
        sink.Session = session;
        CompleteHandshake(session, bytewise: false);
        var frame = EncodeBasic("tx"u8, CreateMinimalTransaction());
        var transactionId = Hash256.DoubleSha256(CreateMinimalTransaction());
        Span<BsvTransactionBroadcastOutput> outputs =
            stackalloc BsvTransactionBroadcastOutput[BsvTransactionBroadcastStateMachine.MaximumOutputCount];
        Assert.AreEqual(OperationStatus.Done, session.StartBroadcast(transactionId));
        Assert.AreEqual(OperationStatus.Done, session.DrainBroadcastOutputs(outputs, out _));
        Assert.AreEqual(OperationStatus.Done, CommitInventoryEgress(session, transactionId));
        Assert.AreEqual(OperationStatus.Done, session.DrainBroadcastOutputs(outputs, out _));
        Assert.AreEqual(OperationStatus.Done, session.StartFetch(transactionId));

        Assert.ThrowsException<InvalidOperationException>(() => session.Consume(frame, out _));
        Assert.AreEqual(1, sink.StartedCount);
        Assert.AreEqual(0, sink.InputStartedCount);
        Assert.AreEqual(0, sink.CommittedCount);
        Assert.AreEqual(BsvTransactionBroadcastState.Terminal, session.BroadcastState);
        Assert.AreEqual(
            BsvTransactionBroadcastTerminalReason.ExternalFailure,
            session.BroadcastTerminalReason);
        Assert.AreEqual(BsvTransactionFetchState.Terminal, session.FetchState);
        Assert.AreEqual(BsvTransactionFetchTerminalReason.ExternalFailure, session.FetchTerminalReason);
        Assert.AreEqual(OperationStatus.InvalidData, session.Consume(frame, out var consumed));
        Assert.AreEqual(0, consumed);
    }

    [TestMethod]
    public void WarmSessionTransactionCallbacksHaveNoCountBasedAllocationSlope()
    {
        var sink = new RecordingTransactionSink();
        using var session = CreateReadySession(sink, bytewise: false);
        var smallFrame = EncodeBasic("tx"u8, CreateMinimalTransaction());
        var manyFrame = EncodeBasic("tx"u8, CreateHighInputCountTransaction(512));
        ConsumeFrame(session, smallFrame, bytewise: false);

        var beforeSmall = GC.GetAllocatedBytesForCurrentThread();
        ConsumeFrame(session, smallFrame, bytewise: false);
        var smallAllocated = GC.GetAllocatedBytesForCurrentThread() - beforeSmall;
        var beforeMany = GC.GetAllocatedBytesForCurrentThread();
        ConsumeFrame(session, manyFrame, bytewise: false);
        var manyAllocated = GC.GetAllocatedBytesForCurrentThread() - beforeMany;

        Assert.IsTrue(
            manyAllocated <= smallAllocated + 256,
            $"Small frame allocated {smallAllocated} bytes; high-count frame allocated {manyAllocated} bytes.");
    }

    [TestMethod]
    public void EndOfInputTerminatesActiveBroadcastAndClearsPendingIntent()
    {
        var sink = new RecordingTransactionSink();
        using var session = CreateReadySession(sink, bytewise: false);
        var transactionId = Hash256.DoubleSha256(CreateMinimalTransaction());
        Assert.AreEqual(OperationStatus.Done, session.StartFetch(transactionId));
        Assert.AreEqual(OperationStatus.Done, session.StartBroadcast(transactionId));
        Assert.AreEqual(1, session.PendingBroadcastOutputCount);

        Assert.AreEqual(OperationStatus.Done, session.CompleteEndOfInput());

        Assert.AreEqual(0, session.PendingBroadcastOutputCount);
        Assert.AreEqual(BsvTransactionBroadcastState.Terminal, session.BroadcastState);
        Assert.AreEqual(
            BsvTransactionBroadcastTerminalReason.Disconnected,
            session.BroadcastTerminalReason);
        Assert.IsFalse(session.IsAnnounced);
        Assert.AreEqual(BsvTransactionFetchState.Terminal, session.FetchState);
        Assert.AreEqual(BsvTransactionFetchTerminalReason.Disconnected, session.FetchTerminalReason);
    }

    [TestMethod]
    public void EarlyReceivedTransactionSupersedesCompletedGetDataWriteWithoutRequestedFact()
    {
        var sink = new RecordingTransactionSink();
        using var session = CreateReadySession(sink, bytewise: false);
        var transaction = CreateMinimalTransaction();
        var transactionId = Hash256.DoubleSha256(transaction);
        Span<BsvTransactionFetchOutput> outputs =
            stackalloc BsvTransactionFetchOutput[BsvTransactionFetchStateMachine.MaximumOutputCount];
        Assert.AreEqual(OperationStatus.Done, session.StartFetch(transactionId));
        ConsumeFrame(session, EncodeInventory("inv"u8, transactionId), bytewise: false);
        DrainFetch(session, outputs, BsvTransactionFetchOutputKind.SendGetData, transactionId);
        Assert.AreEqual(
            OperationStatus.Done,
            session.PlanFetchEgress(
                new BsvTransactionFetchOutput(BsvTransactionFetchOutputKind.SendGetData, transactionId),
                out _));
        DrainEgress(session);

        ConsumeFrame(session, EncodeBasic("tx"u8, transaction), bytewise: false);
        DrainFetch(session, outputs, BsvTransactionFetchOutputKind.Received, transactionId);
        Assert.AreEqual(OperationStatus.Done, session.CommitEgressCompletion());
        Assert.AreEqual(BsvTransactionFetchState.Received, session.FetchState);
        Assert.AreEqual(0, session.PendingFetchOutputCount);
    }

    [TestMethod]
    public void HandshakeEgressCompletionResetsWithoutEnteringRelay()
    {
        using var session = new BsvPeerSessionIngressAdapter(
            NetworkMagic,
            MaximumPayloadLength,
            MinimumProtocolVersion,
            new RecordingTransactionSink());
        Assert.AreEqual(OperationStatus.Done, session.StartHandshake(LocalNonce));
        Span<BsvHandshakeOutput> outputs = stackalloc BsvHandshakeOutput[1];
        Assert.AreEqual(OperationStatus.Done, session.DrainHandshakeOutputs(outputs, out var written));
        Assert.AreEqual(1, written);
        Assert.AreEqual(BsvHandshakeOutputKind.SendVersion, outputs[0].Kind);
        var encodedVersion = CreateVersionPayload(LocalNonce);
        Assert.AreEqual(
            OperationStatus.Done,
            VersionPayloadCodec.TryParse(encodedVersion, out var version, out var consumed));
        Assert.AreEqual(encodedVersion.Length, consumed);

        Assert.AreEqual(OperationStatus.Done, session.PlanVersionEgress(version));
        DrainEgress(session);
        Assert.AreEqual(OperationStatus.Done, session.CommitEgressCompletion());
        Assert.AreEqual(BsvPeerSessionEgressState.Idle, session.EgressState);
        Assert.AreEqual(BsvTransactionBroadcastState.Created, session.BroadcastState);
        Assert.AreEqual(BsvTransactionFetchState.Created, session.FetchState);
        Assert.AreEqual(0, session.PendingBroadcastOutputCount);
        Assert.AreEqual(0, session.PendingFetchOutputCount);
    }

    [TestMethod]
    public void CompletionCapabilityRejectsForgedAndCrossSessionSameValue()
    {
        var transactionId = Hash256.DoubleSha256(CreateMinimalTransaction());
        using var first = CreateReadySession(new RecordingTransactionSink(), bytewise: false);
        using var second = CreateReadySession(new RecordingTransactionSink(), bytewise: false);
        PrepareInventoryCompletion(first, transactionId);
        PrepareInventoryCompletion(second, transactionId);
        var firstPlanner = GetEgressPlanner(first);
        var secondPlanner = GetEgressPlanner(second);
        Assert.IsTrue(firstPlanner.TryPeekCompletion(out var firstCompletion));
        Assert.IsTrue(secondPlanner.TryPeekCompletion(out var secondCompletion));
        Assert.AreEqual(firstCompletion.PlanId, secondCompletion.PlanId);
        var firstOwner = (IBsvPeerSessionEgressCompletionOwner)first;
        var secondOwner = (IBsvPeerSessionEgressCompletionOwner)second;

        Assert.AreEqual(OperationStatus.InvalidData, firstOwner.ApplyEgressCompletion(firstCompletion));
        Assert.IsFalse(first.IsAnnounced);
        Assert.AreEqual(OperationStatus.InvalidData, secondOwner.ApplyEgressCompletion(firstCompletion));
        var forged = new BsvPeerSessionEgressCompletion(
            secondPlanner,
            secondCompletion.PlanId + 1,
            secondCompletion.SendKind,
            secondCompletion.RelayWriteCommitKind,
            secondCompletion.TransactionId,
            secondCompletion.Value);
        Assert.AreEqual(OperationStatus.InvalidData, secondOwner.ApplyEgressCompletion(forged));
        Assert.IsFalse(second.IsAnnounced);
        Assert.AreEqual(OperationStatus.Done, second.CommitEgressCompletion());
        Assert.IsTrue(second.IsAnnounced);
        Assert.IsFalse(first.IsAnnounced);
        Assert.AreEqual(OperationStatus.Done, first.CommitEgressCompletion());
        Assert.IsTrue(first.IsAnnounced);
    }

    [TestMethod]
    public void RelayIntentMustMatchCurrentPhaseBeforeAnyWireBytesExist()
    {
        using var session = CreateReadySession(new RecordingTransactionSink(), bytewise: false);
        var transactionId = Hash256.DoubleSha256(CreateMinimalTransaction());
        var otherId = Hash256.DoubleSha256([0x42]);
        var sendInventory = new BsvTransactionBroadcastOutput(
            BsvTransactionBroadcastOutputKind.SendInventory,
            transactionId);
        Assert.AreEqual(OperationStatus.InvalidData, session.PlanBroadcastEgress(sendInventory, out _));
        Assert.IsTrue(session.PendingEgressSegment.IsEmpty);

        Assert.AreEqual(OperationStatus.Done, session.StartBroadcast(transactionId));
        Span<BsvTransactionBroadcastOutput> outputs =
            stackalloc BsvTransactionBroadcastOutput[BsvTransactionBroadcastStateMachine.MaximumOutputCount];
        DrainBroadcast(session, outputs, BsvTransactionBroadcastOutputKind.SendInventory, transactionId);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            session.PlanBroadcastEgress(
                new BsvTransactionBroadcastOutput(
                    BsvTransactionBroadcastOutputKind.SendInventory,
                    otherId),
                out _));
        Assert.IsTrue(session.PendingEgressSegment.IsEmpty);
        Assert.AreEqual(OperationStatus.Done, session.PlanBroadcastEgress(sendInventory, out _));
    }

    [TestMethod]
    public void PendingOutputPreservesCompletedEgressForRetry()
    {
        using var session = CreateReadySession(new RecordingTransactionSink(), bytewise: false);
        var transactionId = Hash256.DoubleSha256(CreateMinimalTransaction());
        PrepareInventoryCompletion(session, transactionId);
        ConsumeFrame(session, EncodeInventory("inv"u8, transactionId), bytewise: false);

        Assert.AreEqual(OperationStatus.DestinationTooSmall, session.CommitEgressCompletion());
        Assert.AreEqual(BsvPeerSessionEgressState.Complete, session.EgressState);
        Assert.IsFalse(session.IsAnnounced);
        Span<BsvTransactionBroadcastOutput> outputs =
            stackalloc BsvTransactionBroadcastOutput[BsvTransactionBroadcastStateMachine.MaximumOutputCount];
        DrainBroadcast(
            session,
            outputs,
            BsvTransactionBroadcastOutputKind.ObservedFromPeer,
            transactionId);
        Assert.AreEqual(OperationStatus.Done, session.CommitEgressCompletion());
        DrainBroadcast(session, outputs, BsvTransactionBroadcastOutputKind.Announced, transactionId);
        Assert.IsTrue(session.IsAnnounced);
    }

    [TestMethod]
    public void TerminalEgressOperationsReturnStableInvalidData()
    {
        using var completed = CreateReadySession(new RecordingTransactionSink(), bytewise: false);
        Assert.AreEqual(OperationStatus.Done, completed.CompleteEndOfInput());
        Assert.AreEqual(
            OperationStatus.InvalidData,
            completed.ProvideTransactionEgressChunk(new byte[] { 1 }));
        Assert.AreEqual(OperationStatus.InvalidData, completed.AcknowledgeEgress(default, 1));
        Assert.AreEqual(OperationStatus.InvalidData, completed.EndTransactionEgressPayload());
        Assert.AreEqual(OperationStatus.InvalidData, completed.CommitEgressCompletion());
        Assert.AreEqual(OperationStatus.InvalidData, completed.AbortEgress());
        Assert.AreEqual(
            OperationStatus.InvalidData,
            completed.PlanBroadcastEgress(
                new BsvTransactionBroadcastOutput(
                    BsvTransactionBroadcastOutputKind.SendInventory,
                    default),
                out _));

        using var failed = CreateReadySession(new RecordingTransactionSink(), bytewise: false);
        var bad = EncodeInventory("inv"u8, default);
        bad[^1] ^= 0xff;
        Assert.AreEqual(OperationStatus.InvalidData, failed.Consume(bad, out _));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            failed.ProvideTransactionEgressChunk(new byte[] { 1 }));
        Assert.AreEqual(OperationStatus.InvalidData, failed.AcknowledgeEgress(default, 1));
        Assert.AreEqual(OperationStatus.InvalidData, failed.EndTransactionEgressPayload());
        Assert.AreEqual(OperationStatus.InvalidData, failed.CommitEgressCompletion());
        Assert.AreEqual(OperationStatus.InvalidData, failed.AbortEgress());
    }

    [TestMethod]
    public void AdapterOwnsDefaultPeerOutboundMaximum()
    {
        using var session = CreateReadySession(new RecordingTransactionSink(), bytewise: false);
        var transactionId = Hash256.DoubleSha256(CreateMinimalTransaction());
        PrepareTransactionIntent(session, transactionId);

        Assert.AreEqual(
            OperationStatus.InvalidData,
            session.PlanTransactionEgress(
                new BsvTransactionBroadcastOutput(
                    BsvTransactionBroadcastOutputKind.SendTransaction,
                    transactionId),
                BsvHandshakeStateMachine.DefaultPeerMaximumReceivePayloadLength + 1UL,
                transactionId));
        Assert.IsTrue(session.PendingEgressSegment.IsEmpty);

        const uint negotiatedMaximum =
            BsvHandshakeStateMachine.DefaultPeerMaximumReceivePayloadLength * 2;
        using var negotiated = CreateReadySession(
            new RecordingTransactionSink(),
            bytewise: false,
            peerMaximumReceivePayloadLength: negotiatedMaximum);
        PrepareTransactionIntent(negotiated, transactionId);
        Assert.AreEqual(
            OperationStatus.Done,
            negotiated.PlanTransactionEgress(
                new BsvTransactionBroadcastOutput(
                    BsvTransactionBroadcastOutputKind.SendTransaction,
                    transactionId),
                BsvHandshakeStateMachine.DefaultPeerMaximumReceivePayloadLength + 1UL,
                transactionId));
        Assert.IsFalse(negotiated.PendingEgressSegment.IsEmpty);
        Assert.AreEqual(OperationStatus.Done, negotiated.AbortEgress());
    }

    [TestMethod]
    public void OversizedUnknownCommandIsRejectedAfterHeaderWithoutConsumingPayload()
    {
        var sink = new RecordingTransactionSink();
        using var session = CreateReadySession(sink, bytewise: false);
        var header = EncodeBasicHeader(
            "unknown"u8,
            checked((uint)(BsvPeerSessionIngressAdapter.MaximumIgnoredPayloadLength + 1)));
        var source = new byte[header.Length + 1];
        header.CopyTo(source, 0);
        source[^1] = 0x5a;

        Assert.AreEqual(OperationStatus.InvalidData, session.Consume(source, out var consumed));
        Assert.AreEqual(header.Length, consumed);
        Assert.AreEqual(OperationStatus.InvalidData, session.Consume(source.AsSpan(consumed), out consumed));
        Assert.AreEqual(0, consumed);
    }

    private static BsvPeerSessionIngressAdapter CreateReadySession(
        RecordingTransactionSink sink,
        bool bytewise,
        uint? peerMaximumReceivePayloadLength = null)
    {
        var session = new BsvPeerSessionIngressAdapter(
            NetworkMagic,
            MaximumPayloadLength,
            MinimumProtocolVersion,
            sink);
        CompleteHandshake(session, bytewise, peerMaximumReceivePayloadLength);
        return session;
    }

    private static void CompleteHandshake(
        BsvPeerSessionIngressAdapter session,
        bool bytewise,
        uint? peerMaximumReceivePayloadLength = null)
    {
        Assert.AreEqual(OperationStatus.Done, session.StartHandshake(LocalNonce));
        Span<BsvHandshakeOutput> outputs = stackalloc BsvHandshakeOutput[3];
        Assert.AreEqual(OperationStatus.Done, session.DrainHandshakeOutputs(outputs, out var written));
        Assert.AreEqual(1, written);
        Assert.AreEqual(BsvHandshakeOutputKind.SendVersion, outputs[0].Kind);
        CommitLocalVersionEgress(session);

        ConsumeFrame(session, EncodeBasic("version"u8, CreateVersionPayload(PeerNonce)), bytewise);
        Assert.AreEqual(OperationStatus.Done, session.DrainHandshakeOutputs(outputs, out written));
        Assert.AreEqual(2, written);
        Assert.AreEqual(BsvHandshakeOutputKind.SendVerack, outputs[0].Kind);
        Assert.AreEqual(BsvHandshakeOutputKind.SendProtoconf, outputs[1].Kind);
        Assert.AreEqual(OperationStatus.Done, session.PlanNextHandshakeEgress());
        DrainEgress(session);
        Assert.AreEqual(OperationStatus.Done, session.CommitEgressCompletion());
        Assert.AreEqual(
            OperationStatus.Done,
            session.PlanProtoconfEgress(
                checked((uint)MaximumPayloadLength),
                default,
                includeStreamPolicies: false));
        DrainEgress(session);
        Assert.AreEqual(OperationStatus.Done, session.CommitEgressCompletion());

        ConsumeFrame(session, EncodeBasic("verack"u8, []), bytewise);
        Assert.AreEqual(OperationStatus.Done, session.DrainHandshakeOutputs(outputs, out written));
        Assert.AreEqual(1, written);
        Assert.AreEqual(BsvHandshakeOutputKind.BecameReady, outputs[0].Kind);
        Assert.AreEqual(BsvHandshakeState.Ready, session.HandshakeState);

        if (peerMaximumReceivePayloadLength.HasValue)
        {
            Span<byte> protoconf = stackalloc byte[8];
            Assert.AreEqual(
                OperationStatus.Done,
                ProtoconfPayloadCodec.TryWrite(
                    protoconf,
                    peerMaximumReceivePayloadLength.Value,
                    default,
                    includeStreamPolicies: false,
                    out var protoconfLength));
            ConsumeFrame(
                session,
                EncodeBasic("protoconf"u8, protoconf[..protoconfLength]),
                bytewise);
            Assert.AreEqual(
                peerMaximumReceivePayloadLength.Value,
                session.EffectivePeerMaximumReceivePayloadLength);
        }
    }

    private static void CommitLocalVersionEgress(BsvPeerSessionIngressAdapter session)
    {
        var encodedVersion = CreateVersionPayload(LocalNonce);
        Assert.AreEqual(
            OperationStatus.Done,
            VersionPayloadCodec.TryParse(encodedVersion, out var version, out var consumed));
        Assert.AreEqual(encodedVersion.Length, consumed);
        Assert.AreEqual(OperationStatus.Done, session.PlanVersionEgress(version));
        DrainEgress(session);
        Assert.AreEqual(OperationStatus.Done, session.CommitEgressCompletion());
    }

    private static void ConsumeFrame(
        BsvPeerSessionIngressAdapter session,
        ReadOnlySpan<byte> frame,
        bool bytewise)
    {
        if (!bytewise)
        {
            Assert.AreEqual(OperationStatus.Done, session.Consume(frame, out var consumed));
            Assert.AreEqual(frame.Length, consumed);
            return;
        }

        for (var index = 0; index < frame.Length; index++)
        {
            var status = session.Consume(frame.Slice(index, 1), out var consumed);
            Assert.AreEqual(1, consumed, $"byte {index}");
            Assert.AreEqual(
                index == frame.Length - 1 ? OperationStatus.Done : OperationStatus.NeedMoreData,
                status,
                $"byte {index}");
        }
    }

    private static OperationStatus CommitInventoryEgress(
        BsvPeerSessionIngressAdapter session,
        Hash256 transactionId)
    {
        var status = session.PlanBroadcastEgress(
            new BsvTransactionBroadcastOutput(
                BsvTransactionBroadcastOutputKind.SendInventory,
                transactionId),
            out var disposition);
        Assert.AreEqual(BsvPeerSessionOutputDisposition.Send, disposition);
        if (status != OperationStatus.Done)
        {
            return status;
        }

        DrainEgress(session);
        return session.CommitEgressCompletion();
    }

    private static void PrepareInventoryCompletion(
        BsvPeerSessionIngressAdapter session,
        Hash256 transactionId)
    {
        Assert.AreEqual(OperationStatus.Done, session.StartBroadcast(transactionId));
        Span<BsvTransactionBroadcastOutput> outputs =
            stackalloc BsvTransactionBroadcastOutput[BsvTransactionBroadcastStateMachine.MaximumOutputCount];
        DrainBroadcast(session, outputs, BsvTransactionBroadcastOutputKind.SendInventory, transactionId);
        Assert.AreEqual(
            OperationStatus.Done,
            session.PlanBroadcastEgress(
                new BsvTransactionBroadcastOutput(
                    BsvTransactionBroadcastOutputKind.SendInventory,
                    transactionId),
                out _));
        DrainEgress(session);
        Assert.AreEqual(BsvPeerSessionEgressState.Complete, session.EgressState);
    }

    private static void PrepareTransactionIntent(
        BsvPeerSessionIngressAdapter session,
        Hash256 transactionId)
    {
        Assert.AreEqual(OperationStatus.Done, session.StartBroadcast(transactionId));
        Span<BsvTransactionBroadcastOutput> outputs =
            stackalloc BsvTransactionBroadcastOutput[BsvTransactionBroadcastStateMachine.MaximumOutputCount];
        DrainBroadcast(session, outputs, BsvTransactionBroadcastOutputKind.SendInventory, transactionId);
        Assert.AreEqual(OperationStatus.Done, CommitInventoryEgress(session, transactionId));
        DrainBroadcast(session, outputs, BsvTransactionBroadcastOutputKind.Announced, transactionId);
        ConsumeFrame(session, EncodeInventory("getdata"u8, transactionId), bytewise: false);
        Assert.AreEqual(OperationStatus.Done, session.DrainBroadcastOutputs(outputs, out var written));
        Assert.AreEqual(2, written);
        Assert.AreEqual(BsvTransactionBroadcastOutputKind.RequestedByPeer, outputs[0].Kind);
        Assert.AreEqual(BsvTransactionBroadcastOutputKind.SendTransaction, outputs[1].Kind);
    }

    private static BsvPeerSessionEgressPlanner GetEgressPlanner(
        BsvPeerSessionIngressAdapter session)
    {
        var field = typeof(BsvPeerSessionIngressAdapter).GetField(
            "_egress",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        Assert.IsNotNull(field);
        return (BsvPeerSessionEgressPlanner)field.GetValue(session)!;
    }

    private static OperationStatus CommitTransactionEgress(
        BsvPeerSessionIngressAdapter session,
        ReadOnlyMemory<byte> transaction,
        Hash256 transactionId)
    {
        var status = session.PlanTransactionEgress(
            new BsvTransactionBroadcastOutput(
                BsvTransactionBroadcastOutputKind.SendTransaction,
                transactionId),
            (ulong)transaction.Length,
            transactionId);
        if (status != OperationStatus.Done)
        {
            return status;
        }

        Assert.AreEqual(
            OperationStatus.Done,
            session.AcknowledgeEgress(session.PendingEgressSegment, session.PendingEgressSegment.Length));
        Assert.AreEqual(OperationStatus.Done, session.ProvideTransactionEgressChunk(transaction));
        Assert.AreEqual(
            OperationStatus.Done,
            session.AcknowledgeEgress(session.PendingEgressSegment, session.PendingEgressSegment.Length));
        return session.CommitEgressCompletion();
    }

    private static OperationStatus CommitGetDataEgress(
        BsvPeerSessionIngressAdapter session,
        Hash256 transactionId)
    {
        var status = session.PlanFetchEgress(
            new BsvTransactionFetchOutput(BsvTransactionFetchOutputKind.SendGetData, transactionId),
            out var disposition);
        Assert.AreEqual(BsvPeerSessionOutputDisposition.Send, disposition);
        if (status != OperationStatus.Done)
        {
            return status;
        }

        DrainEgress(session);
        return session.CommitEgressCompletion();
    }

    private static void DrainEgress(BsvPeerSessionIngressAdapter session)
    {
        while (!session.PendingEgressSegment.IsEmpty)
        {
            var pending = session.PendingEgressSegment;
            Assert.AreEqual(OperationStatus.Done, session.AcknowledgeEgress(pending, pending.Length));
        }
    }

    private static void DrainBroadcast(
        BsvPeerSessionIngressAdapter session,
        Span<BsvTransactionBroadcastOutput> destination,
        BsvTransactionBroadcastOutputKind expectedKind,
        Hash256 expectedTransactionId)
    {
        Assert.AreEqual(OperationStatus.Done, session.DrainBroadcastOutputs(destination, out var written));
        Assert.AreEqual(1, written);
        Assert.AreEqual(expectedKind, destination[0].Kind);
        Assert.AreEqual(expectedTransactionId, destination[0].TransactionId);
    }

    private static void DrainFetch(
        BsvPeerSessionIngressAdapter session,
        Span<BsvTransactionFetchOutput> destination,
        BsvTransactionFetchOutputKind expectedKind,
        Hash256 expectedTransactionId)
    {
        Assert.AreEqual(OperationStatus.Done, session.DrainFetchOutputs(destination, out var written));
        Assert.AreEqual(1, written);
        Assert.AreEqual(expectedKind, destination[0].Kind);
        Assert.AreEqual(expectedTransactionId, destination[0].TransactionId);
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
        Assert.AreEqual(OperationStatus.Done, VersionPayloadCodec.TryWrite(payload, version, out var written));
        return payload[..written];
    }

    private static byte[] EncodeInventory(
        ReadOnlySpan<byte> command,
        Hash256 transactionId,
        uint type = 1)
    {
        var payload = new byte[1 + InventoryVectorCodec.EncodedLength];
        var vectors = new[] { new InventoryVector(type, transactionId) };
        Assert.AreEqual(
            OperationStatus.Done,
            InventoryPayloadCodec.TryWrite(vectors, payload, (ulong)payload.Length, out var written));
        Assert.AreEqual(payload.Length, written);
        return EncodeBasic(command, payload);
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
                out var written));
        Assert.AreEqual(destination.Length, written);
        return destination;
    }

    private static byte[] CreateMinimalTransaction()
    {
        var transaction = new byte[60];
        BinaryPrimitives.WriteInt32LittleEndian(transaction, 1);
        transaction[4] = 1;
        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(37), uint.MaxValue);
        transaction[41] = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(42), uint.MaxValue);
        transaction[46] = 1;
        BinaryPrimitives.WriteInt64LittleEndian(transaction.AsSpan(47), 1);
        transaction[55] = 0;
        return transaction;
    }

    private static byte[] CreateHighInputCountTransaction(int inputCount)
    {
        const int compactCountLength = 3;
        const int inputLength = Hash256.Length + sizeof(uint) + 1 + sizeof(uint);
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
            transaction[offset++] = 0;
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

    private sealed class RecordingTransactionSink : ILegacyTransactionSink
    {
        public int CommittedCount { get; private set; }

        public int AbortedCount { get; private set; }

        public LegacyTransactionSummary LastSummary { get; private set; }

        public void OnTransactionStarted(int version, ulong inputCount)
        {
        }

        public void OnInputStarted(ulong inputIndex, in OutPoint previousOutput, ulong scriptLength)
        {
        }

        public void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script)
        {
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
        }

        public void OnOutputCompleted(ulong outputIndex)
        {
        }

        public void OnTransactionCommitted(in LegacyTransactionSummary summary)
        {
            CommittedCount++;
            LastSummary = summary;
        }

        public void OnTransactionAborted() => AbortedCount++;
    }

    private sealed class ReenteringTransactionSink : ILegacyTransactionSink
    {
        public BsvPeerSessionIngressAdapter? Session { get; set; }

        public int StartedCount { get; private set; }

        public int InputStartedCount { get; private set; }

        public int CommittedCount { get; private set; }

        public void OnTransactionStarted(int version, ulong inputCount)
        {
            StartedCount++;
            try
            {
                _ = Session!.StartBroadcast(default);
            }
            catch (InvalidOperationException)
            {
            }

            try
            {
                _ = Session!.Consume([], out _);
            }
            catch (InvalidOperationException)
            {
            }

            try
            {
                Session!.Dispose();
            }
            catch (InvalidOperationException)
            {
            }
        }

        public void OnInputStarted(ulong inputIndex, in OutPoint previousOutput, ulong scriptLength) =>
            InputStartedCount++;

        public void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script)
        {
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
        }

        public void OnOutputCompleted(ulong outputIndex)
        {
        }

        public void OnTransactionCommitted(in LegacyTransactionSummary summary) => CommittedCount++;

        public void OnTransactionAborted()
        {
        }
    }
}
