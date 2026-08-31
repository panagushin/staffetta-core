using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Relay;

namespace Staffetta.Core.Tests.Protocol.Relay;

[TestClass]
public sealed class BsvTransactionBroadcastStateMachineTests
{
    private static readonly Hash256 Target = CreateHash(1);
    private static readonly Hash256 Other = CreateHash(2);

    [TestMethod]
    public void StartAndInventoryCommitSeparateIntentFromAnnouncedFact()
    {
        var machine = new BsvTransactionBroadcastStateMachine();

        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Start(Target, Span<BsvTransactionBroadcastOutput>.Empty, out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.AreEqual(BsvTransactionBroadcastState.Created, machine.State);

        Span<BsvTransactionBroadcastOutput> output = stackalloc BsvTransactionBroadcastOutput[1];
        Assert.AreEqual(OperationStatus.Done, machine.Start(Target, output, out var startWritten));
        AssertOutput(output[0], BsvTransactionBroadcastOutputKind.SendInventory, Target);
        Assert.AreEqual(1, startWritten);
        Assert.AreEqual(BsvTransactionBroadcastState.InventoryWritePending, machine.State);
        Assert.IsFalse(machine.IsAnnounced);

        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Apply(
                BsvTransactionBroadcastInput.InventoryWriteCommitted(Target),
                Span<BsvTransactionBroadcastOutput>.Empty,
                out shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.IsFalse(machine.IsAnnounced);

        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(
                BsvTransactionBroadcastInput.InventoryWriteCommitted(Target),
                output,
                out var commitWritten));
        Assert.AreEqual(1, commitWritten);
        AssertOutput(output[0], BsvTransactionBroadcastOutputKind.Announced, Target);
        Assert.IsTrue(machine.IsAnnounced);
        Assert.AreEqual(BsvTransactionBroadcastState.Announced, machine.State);

        Assert.AreEqual(
            OperationStatus.InvalidData,
            machine.Apply(
                BsvTransactionBroadcastInput.InventoryWriteCommitted(Target),
                output,
                out var staleWritten));
        Assert.AreEqual(0, staleWritten);
        Assert.AreEqual(BsvTransactionBroadcastState.Announced, machine.State);
    }

    [TestMethod]
    public void GetDataAfterAnnounceProducesAtomicSingleFlightTransactionIntent()
    {
        var machine = CreateAnnouncedMachine();
        Span<BsvTransactionBroadcastOutput> shortOutput = stackalloc BsvTransactionBroadcastOutput[1];

        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Apply(
                BsvTransactionBroadcastInput.PeerGetData(Target),
                shortOutput,
                out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.IsFalse(machine.WasRequestedByPeer);
        Assert.AreEqual(BsvTransactionBroadcastState.Announced, machine.State);

        Span<BsvTransactionBroadcastOutput> output = stackalloc BsvTransactionBroadcastOutput[2];
        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(
                BsvTransactionBroadcastInput.PeerGetData(Target),
                output,
                out var outputsWritten));
        Assert.AreEqual(2, outputsWritten);
        AssertOutput(output[0], BsvTransactionBroadcastOutputKind.RequestedByPeer, Target);
        AssertOutput(output[1], BsvTransactionBroadcastOutputKind.SendTransaction, Target);
        Assert.IsTrue(machine.WasRequestedByPeer);
        Assert.AreEqual(BsvTransactionBroadcastState.TransactionWritePending, machine.State);

        AssertDoneWithoutOutput(machine, BsvTransactionBroadcastInput.PeerGetData(Target));
        AssertDoneWithoutOutput(machine, BsvTransactionBroadcastInput.PeerGetData(Other));
        Assert.IsFalse(machine.IsSentToPeer);

        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(
                BsvTransactionBroadcastInput.TransactionWriteCommitted(Target),
                output,
                out var commitWritten));
        Assert.AreEqual(1, commitWritten);
        AssertOutput(output[0], BsvTransactionBroadcastOutputKind.SentToPeer, Target);
        Assert.IsTrue(machine.IsSentToPeer);
        Assert.AreEqual(BsvTransactionBroadcastState.SentToPeer, machine.State);
    }

    [TestMethod]
    public void GetDataRacingInventoryCommitIsDeferredAndResolvedAtomically()
    {
        var machine = CreateStartedMachine();
        AssertDoneWithoutOutput(machine, BsvTransactionBroadcastInput.PeerGetData(Target));

        Span<BsvTransactionBroadcastOutput> shortOutput = stackalloc BsvTransactionBroadcastOutput[2];
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Apply(
                BsvTransactionBroadcastInput.InventoryWriteCommitted(Target),
                shortOutput,
                out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.IsFalse(machine.IsAnnounced);
        Assert.IsFalse(machine.WasRequestedByPeer);
        Assert.AreEqual(BsvTransactionBroadcastState.InventoryWritePending, machine.State);

        Span<BsvTransactionBroadcastOutput> output = stackalloc BsvTransactionBroadcastOutput[3];
        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(
                BsvTransactionBroadcastInput.InventoryWriteCommitted(Target),
                output,
                out var outputsWritten));
        Assert.AreEqual(3, outputsWritten);
        AssertOutput(output[0], BsvTransactionBroadcastOutputKind.Announced, Target);
        AssertOutput(output[1], BsvTransactionBroadcastOutputKind.RequestedByPeer, Target);
        AssertOutput(output[2], BsvTransactionBroadcastOutputKind.SendTransaction, Target);
        Assert.IsTrue(machine.IsAnnounced);
        Assert.IsTrue(machine.WasRequestedByPeer);
        Assert.AreEqual(BsvTransactionBroadcastState.TransactionWritePending, machine.State);
    }

    [TestMethod]
    public void InventoryObservationIsOrthogonalDeduplicatedAndNeverCalledRelayed()
    {
        var machine = CreateStartedMachine();
        Span<BsvTransactionBroadcastOutput> output = stackalloc BsvTransactionBroadcastOutput[1];

        AssertDoneWithoutOutput(machine, BsvTransactionBroadcastInput.PeerInventory(Other));
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Apply(
                BsvTransactionBroadcastInput.PeerInventory(Target),
                Span<BsvTransactionBroadcastOutput>.Empty,
                out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.IsFalse(machine.WasObservedFromPeer);

        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(
                BsvTransactionBroadcastInput.PeerInventory(Target),
                output,
                out var outputsWritten));
        Assert.AreEqual(1, outputsWritten);
        AssertOutput(output[0], BsvTransactionBroadcastOutputKind.ObservedFromPeer, Target);
        Assert.IsTrue(machine.WasObservedFromPeer);
        Assert.AreEqual(BsvTransactionBroadcastState.InventoryWritePending, machine.State);
        AssertDoneWithoutOutput(machine, BsvTransactionBroadcastInput.PeerInventory(Target));

        CollectionAssert.DoesNotContain(
            Enum.GetNames<BsvTransactionBroadcastOutputKind>(),
            "Relayed");
    }

    [TestMethod]
    public void RejectIsCorrelatedAndCannotPrecedeCommittedTransactionWrite()
    {
        var early = CreateAnnouncedMachine();
        AssertDoneWithoutOutput(early, BsvTransactionBroadcastInput.CorrelatedTransactionReject(Target));
        Assert.AreEqual(BsvTransactionBroadcastState.Announced, early.State);

        var machine = CreateTransactionWritePendingMachine();
        AssertDoneWithoutOutput(machine, BsvTransactionBroadcastInput.CorrelatedTransactionReject(Other));
        AssertDoneWithoutOutput(machine, BsvTransactionBroadcastInput.CorrelatedTransactionReject(Target));

        Span<BsvTransactionBroadcastOutput> shortOutput = stackalloc BsvTransactionBroadcastOutput[1];
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Apply(
                BsvTransactionBroadcastInput.TransactionWriteCommitted(Target),
                shortOutput,
                out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.IsFalse(machine.IsSentToPeer);
        Assert.IsFalse(machine.IsRejected);

        Span<BsvTransactionBroadcastOutput> output = stackalloc BsvTransactionBroadcastOutput[2];
        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(
                BsvTransactionBroadcastInput.TransactionWriteCommitted(Target),
                output,
                out var outputsWritten));
        Assert.AreEqual(2, outputsWritten);
        AssertOutput(output[0], BsvTransactionBroadcastOutputKind.SentToPeer, Target);
        AssertOutput(output[1], BsvTransactionBroadcastOutputKind.Rejected, Target);
        Assert.IsTrue(machine.IsSentToPeer);
        Assert.IsTrue(machine.IsRejected);
        Assert.AreEqual(BsvTransactionBroadcastState.Terminal, machine.State);
        Assert.AreEqual(BsvTransactionBroadcastTerminalReason.Rejected, machine.TerminalReason);

        var afterCommit = CreateTransactionWritePendingMachine();
        Span<BsvTransactionBroadcastOutput> committedOutput = stackalloc BsvTransactionBroadcastOutput[1];
        Assert.AreEqual(
            OperationStatus.Done,
            afterCommit.Apply(
                BsvTransactionBroadcastInput.TransactionWriteCommitted(Target),
                committedOutput,
                out var committedWritten));
        Assert.AreEqual(1, committedWritten);
        AssertSingleOutputIsAtomic(
            afterCommit,
            BsvTransactionBroadcastInput.CorrelatedTransactionReject(Target),
            BsvTransactionBroadcastOutputKind.Rejected);
        Assert.AreEqual(BsvTransactionBroadcastState.Terminal, afterCommit.State);
    }

    [TestMethod]
    public void FailuresTerminateWithoutPromotingPendingIntentsToFacts()
    {
        var cases = new[]
        {
            (BsvTransactionBroadcastInput.Disconnected(), BsvTransactionBroadcastTerminalReason.Disconnected),
            (BsvTransactionBroadcastInput.WireViolation(), BsvTransactionBroadcastTerminalReason.WireViolation),
            (BsvTransactionBroadcastInput.ExternalFailure(), BsvTransactionBroadcastTerminalReason.ExternalFailure),
        };

        foreach (var (input, reason) in cases)
        {
            var machine = CreateTransactionWritePendingMachine();
            AssertDoneWithoutOutput(machine, input);
            Assert.AreEqual(BsvTransactionBroadcastState.Terminal, machine.State);
            Assert.AreEqual(reason, machine.TerminalReason);
            Assert.IsTrue(machine.IsAnnounced);
            Assert.IsTrue(machine.WasRequestedByPeer);
            Assert.IsFalse(machine.IsSentToPeer);
        }
    }

    private static BsvTransactionBroadcastStateMachine CreateStartedMachine()
    {
        var machine = new BsvTransactionBroadcastStateMachine();
        Span<BsvTransactionBroadcastOutput> output = stackalloc BsvTransactionBroadcastOutput[1];
        Assert.AreEqual(OperationStatus.Done, machine.Start(Target, output, out var outputsWritten));
        Assert.AreEqual(1, outputsWritten);
        return machine;
    }

    private static BsvTransactionBroadcastStateMachine CreateAnnouncedMachine()
    {
        var machine = CreateStartedMachine();
        Span<BsvTransactionBroadcastOutput> output = stackalloc BsvTransactionBroadcastOutput[1];
        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(
                BsvTransactionBroadcastInput.InventoryWriteCommitted(Target),
                output,
                out var outputsWritten));
        Assert.AreEqual(1, outputsWritten);
        return machine;
    }

    private static BsvTransactionBroadcastStateMachine CreateTransactionWritePendingMachine()
    {
        var machine = CreateAnnouncedMachine();
        Span<BsvTransactionBroadcastOutput> output = stackalloc BsvTransactionBroadcastOutput[2];
        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(
                BsvTransactionBroadcastInput.PeerGetData(Target),
                output,
                out var outputsWritten));
        Assert.AreEqual(2, outputsWritten);
        return machine;
    }

    private static void AssertDoneWithoutOutput(
        BsvTransactionBroadcastStateMachine machine,
        BsvTransactionBroadcastInput input)
    {
        Span<BsvTransactionBroadcastOutput> output = stackalloc BsvTransactionBroadcastOutput[3];
        Assert.AreEqual(OperationStatus.Done, machine.Apply(input, output, out var outputsWritten));
        Assert.AreEqual(0, outputsWritten);
    }

    private static void AssertSingleOutputIsAtomic(
        BsvTransactionBroadcastStateMachine machine,
        BsvTransactionBroadcastInput input,
        BsvTransactionBroadcastOutputKind kind)
    {
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Apply(input, Span<BsvTransactionBroadcastOutput>.Empty, out var shortWritten));
        Assert.AreEqual(0, shortWritten);

        Span<BsvTransactionBroadcastOutput> output = stackalloc BsvTransactionBroadcastOutput[1];
        Assert.AreEqual(OperationStatus.Done, machine.Apply(input, output, out var outputsWritten));
        Assert.AreEqual(1, outputsWritten);
        AssertOutput(output[0], kind, Target);
    }

    private static void AssertOutput(
        BsvTransactionBroadcastOutput output,
        BsvTransactionBroadcastOutputKind kind,
        Hash256 transactionId)
    {
        Assert.AreEqual(kind, output.Kind);
        Assert.AreEqual(transactionId, output.TransactionId);
    }

    private static Hash256 CreateHash(byte fill)
    {
        Span<byte> bytes = stackalloc byte[Hash256.Length];
        bytes.Fill(fill);
        Assert.AreEqual(OperationStatus.Done, Hash256.TryCreate(bytes, out var hash));
        return hash;
    }
}
