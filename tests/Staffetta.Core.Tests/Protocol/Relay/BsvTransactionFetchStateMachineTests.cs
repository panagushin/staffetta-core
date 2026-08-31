using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Relay;

namespace Staffetta.Core.Tests.Protocol.Relay;

[TestClass]
public sealed class BsvTransactionFetchStateMachineTests
{
    private static readonly Hash256 Target = CreateHash(3);
    private static readonly Hash256 Other = CreateHash(4);

    [TestMethod]
    public void MatchingInventoryStartsOneGetDataAndCommitPublishesRequestFact()
    {
        var machine = CreateStartedMachine();
        AssertDoneWithoutOutput(machine, BsvTransactionFetchInput.PeerInventory(Other));

        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Apply(
                BsvTransactionFetchInput.PeerInventory(Target),
                Span<BsvTransactionFetchOutput>.Empty,
                out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.AreEqual(BsvTransactionFetchState.AwaitingInventory, machine.State);

        Span<BsvTransactionFetchOutput> output = stackalloc BsvTransactionFetchOutput[1];
        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(
                BsvTransactionFetchInput.PeerInventory(Target),
                output,
                out var inventoryWritten));
        Assert.AreEqual(1, inventoryWritten);
        AssertOutput(output[0], BsvTransactionFetchOutputKind.SendGetData, Target);
        Assert.AreEqual(BsvTransactionFetchState.GetDataWritePending, machine.State);
        AssertDoneWithoutOutput(machine, BsvTransactionFetchInput.PeerInventory(Target));

        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Apply(
                BsvTransactionFetchInput.GetDataWriteCommitted(Target),
                Span<BsvTransactionFetchOutput>.Empty,
                out shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.AreEqual(BsvTransactionFetchState.GetDataWritePending, machine.State);

        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(
                BsvTransactionFetchInput.GetDataWriteCommitted(Target),
                output,
                out var commitWritten));
        Assert.AreEqual(1, commitWritten);
        AssertOutput(output[0], BsvTransactionFetchOutputKind.Requested, Target);
        Assert.AreEqual(BsvTransactionFetchState.Requested, machine.State);

        Assert.AreEqual(
            OperationStatus.InvalidData,
            machine.Apply(
                BsvTransactionFetchInput.GetDataWriteCommitted(Target),
                output,
                out var staleWritten));
        Assert.AreEqual(0, staleWritten);
        Assert.AreEqual(BsvTransactionFetchState.Requested, machine.State);
    }

    [TestMethod]
    public void MatchingValidatedTransactionIsTruthEvenBeforeRequestWriteCommit()
    {
        var beforeInventory = CreateStartedMachine();
        AssertSingleOutput(
            beforeInventory,
            BsvTransactionFetchInput.PeerTransaction(Target),
            BsvTransactionFetchOutputKind.Received,
            Target);
        Assert.AreEqual(BsvTransactionFetchState.Received, beforeInventory.State);

        var writePending = CreateGetDataWritePendingMachine();
        AssertSingleOutput(
            writePending,
            BsvTransactionFetchInput.PeerTransaction(Target),
            BsvTransactionFetchOutputKind.Received,
            Target);
        Assert.AreEqual(BsvTransactionFetchState.Received, writePending.State);
        AssertDoneWithoutOutput(
            writePending,
            BsvTransactionFetchInput.GetDataWriteCommitted(Target));
        Assert.AreEqual(BsvTransactionFetchState.Received, writePending.State);
    }

    [TestMethod]
    public void MismatchedTransactionIsSurfacedAndOutstandingRequestRemains()
    {
        var machine = CreateRequestedMachine();

        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Apply(
                BsvTransactionFetchInput.PeerTransaction(Other),
                Span<BsvTransactionFetchOutput>.Empty,
                out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.AreEqual(BsvTransactionFetchState.Requested, machine.State);

        AssertSingleOutput(
            machine,
            BsvTransactionFetchInput.PeerTransaction(Other),
            BsvTransactionFetchOutputKind.UnexpectedTransaction,
            Other);
        Assert.AreEqual(BsvTransactionFetchState.Requested, machine.State);

        AssertSingleOutput(
            machine,
            BsvTransactionFetchInput.PeerTransaction(Target),
            BsvTransactionFetchOutputKind.Received,
            Target);
        Assert.AreEqual(BsvTransactionFetchState.Received, machine.State);
    }

    [TestMethod]
    public void NotFoundRacingGetDataCommitIsDeferredAndResolvedAtomically()
    {
        var machine = CreateGetDataWritePendingMachine();
        AssertDoneWithoutOutput(machine, BsvTransactionFetchInput.PeerNotFound(Other));
        AssertDoneWithoutOutput(machine, BsvTransactionFetchInput.PeerNotFound(Target));

        Span<BsvTransactionFetchOutput> shortOutput = stackalloc BsvTransactionFetchOutput[1];
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Apply(
                BsvTransactionFetchInput.GetDataWriteCommitted(Target),
                shortOutput,
                out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.AreEqual(BsvTransactionFetchState.GetDataWritePending, machine.State);

        Span<BsvTransactionFetchOutput> output = stackalloc BsvTransactionFetchOutput[2];
        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(
                BsvTransactionFetchInput.GetDataWriteCommitted(Target),
                output,
                out var outputsWritten));
        Assert.AreEqual(2, outputsWritten);
        AssertOutput(output[0], BsvTransactionFetchOutputKind.Requested, Target);
        AssertOutput(output[1], BsvTransactionFetchOutputKind.NotFound, Target);
        Assert.AreEqual(BsvTransactionFetchState.NotFound, machine.State);
    }

    [TestMethod]
    public void NotFoundIsIgnoredBeforeARequestAndTerminatesOnlyAfterCommit()
    {
        var early = CreateStartedMachine();
        AssertDoneWithoutOutput(early, BsvTransactionFetchInput.PeerNotFound(Target));
        Assert.AreEqual(BsvTransactionFetchState.AwaitingInventory, early.State);

        var requested = CreateRequestedMachine();
        AssertDoneWithoutOutput(requested, BsvTransactionFetchInput.PeerNotFound(Other));
        AssertSingleOutput(
            requested,
            BsvTransactionFetchInput.PeerNotFound(Target),
            BsvTransactionFetchOutputKind.NotFound,
            Target);
        Assert.AreEqual(BsvTransactionFetchState.NotFound, requested.State);
    }

    [TestMethod]
    public void DisconnectAndFailuresAreTerminalWithoutRetryPolicy()
    {
        var cases = new[]
        {
            (BsvTransactionFetchInput.Disconnected(), BsvTransactionFetchTerminalReason.Disconnected),
            (BsvTransactionFetchInput.WireViolation(), BsvTransactionFetchTerminalReason.WireViolation),
            (BsvTransactionFetchInput.ExternalFailure(), BsvTransactionFetchTerminalReason.ExternalFailure),
        };

        foreach (var (input, reason) in cases)
        {
            var machine = CreateRequestedMachine();
            AssertDoneWithoutOutput(machine, input);
            Assert.AreEqual(BsvTransactionFetchState.Terminal, machine.State);
            Assert.AreEqual(reason, machine.TerminalReason);
            AssertDoneWithoutOutput(machine, BsvTransactionFetchInput.PeerInventory(Target));
        }
    }

    private static BsvTransactionFetchStateMachine CreateStartedMachine()
    {
        var machine = new BsvTransactionFetchStateMachine();
        Assert.AreEqual(OperationStatus.Done, machine.Start(Target));
        Assert.AreEqual(BsvTransactionFetchState.AwaitingInventory, machine.State);
        Assert.AreEqual(OperationStatus.InvalidData, machine.Start(Other));
        return machine;
    }

    private static BsvTransactionFetchStateMachine CreateGetDataWritePendingMachine()
    {
        var machine = CreateStartedMachine();
        AssertSingleOutput(
            machine,
            BsvTransactionFetchInput.PeerInventory(Target),
            BsvTransactionFetchOutputKind.SendGetData,
            Target);
        return machine;
    }

    private static BsvTransactionFetchStateMachine CreateRequestedMachine()
    {
        var machine = CreateGetDataWritePendingMachine();
        AssertSingleOutput(
            machine,
            BsvTransactionFetchInput.GetDataWriteCommitted(Target),
            BsvTransactionFetchOutputKind.Requested,
            Target);
        return machine;
    }

    private static void AssertSingleOutput(
        BsvTransactionFetchStateMachine machine,
        BsvTransactionFetchInput input,
        BsvTransactionFetchOutputKind kind,
        Hash256 transactionId)
    {
        Span<BsvTransactionFetchOutput> output = stackalloc BsvTransactionFetchOutput[1];
        Assert.AreEqual(OperationStatus.Done, machine.Apply(input, output, out var outputsWritten));
        Assert.AreEqual(1, outputsWritten);
        AssertOutput(output[0], kind, transactionId);
    }

    private static void AssertDoneWithoutOutput(
        BsvTransactionFetchStateMachine machine,
        BsvTransactionFetchInput input)
    {
        Span<BsvTransactionFetchOutput> output = stackalloc BsvTransactionFetchOutput[2];
        Assert.AreEqual(OperationStatus.Done, machine.Apply(input, output, out var outputsWritten));
        Assert.AreEqual(0, outputsWritten);
    }

    private static void AssertOutput(
        BsvTransactionFetchOutput output,
        BsvTransactionFetchOutputKind kind,
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
