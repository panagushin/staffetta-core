using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Handshake;

namespace Staffetta.Core.Tests.Protocol.Handshake;

[TestClass]
public sealed class BsvHandshakeStateMachineTests
{
    private const int MinimumProtocolVersion = 70_016;
    private const ulong LocalNonce = 0x0102_0304_0506_0708;
    private const ulong PeerNonce = 0x1112_1314_1516_1718;

    [TestMethod]
    public void StartIsAtomicAndCanSucceedOnlyOnce()
    {
        var machine = CreateMachine();

        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Start(LocalNonce, Span<BsvHandshakeOutput>.Empty, out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.AreEqual(BsvHandshakeState.Created, machine.State);

        Span<BsvHandshakeOutput> output = stackalloc BsvHandshakeOutput[1];
        Assert.AreEqual(OperationStatus.Done, machine.Start(LocalNonce, output, out var outputsWritten));
        AssertOutputs(output[..outputsWritten], (BsvHandshakeOutputKind.SendVersion, LocalNonce));
        Assert.AreEqual(BsvHandshakeState.Negotiating, machine.State);

        Assert.AreEqual(
            OperationStatus.InvalidData,
            machine.Start(LocalNonce + 1, output, out var duplicateWritten));
        Assert.AreEqual(0, duplicateWritten);
        Assert.AreEqual(BsvHandshakeState.Negotiating, machine.State);
    }

    [TestMethod]
    public void VersionThenVerackBecomesReadyInOrderAndIsRetryableAtEveryOutputBoundary()
    {
        var machine = CreateStartedMachine();
        var sentinel = new BsvHandshakeOutput((BsvHandshakeOutputKind)byte.MaxValue, ulong.MaxValue);
        Span<BsvHandshakeOutput> shortOutput = stackalloc BsvHandshakeOutput[1];
        shortOutput.Fill(sentinel);

        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Apply(
                BsvHandshakeInput.PeerVersion(MinimumProtocolVersion, PeerNonce),
                shortOutput,
                out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.AreEqual(sentinel, shortOutput[0]);
        Assert.IsFalse(machine.HasPeerVersion);
        Assert.AreEqual(BsvHandshakeState.Negotiating, machine.State);

        Span<BsvHandshakeOutput> versionOutput = stackalloc BsvHandshakeOutput[2];
        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(
                BsvHandshakeInput.PeerVersion(MinimumProtocolVersion, PeerNonce),
                versionOutput,
                out var versionWritten));
        AssertOutputs(
            versionOutput[..versionWritten],
            (BsvHandshakeOutputKind.SendVerack, 0),
            (BsvHandshakeOutputKind.SendProtoconf, 0));
        Assert.AreEqual(MinimumProtocolVersion, machine.PeerProtocolVersion);
        Assert.AreEqual(PeerNonce, machine.PeerNonce);

        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Apply(
                BsvHandshakeInput.PeerVerack(),
                Span<BsvHandshakeOutput>.Empty,
                out shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.IsFalse(machine.HasPeerVerack);
        Assert.AreEqual(BsvHandshakeState.Negotiating, machine.State);

        Span<BsvHandshakeOutput> readyOutput = stackalloc BsvHandshakeOutput[1];
        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(BsvHandshakeInput.PeerVerack(), readyOutput, out var readyWritten));
        AssertOutputs(readyOutput[..readyWritten], (BsvHandshakeOutputKind.BecameReady, 0));
        Assert.AreEqual(BsvHandshakeState.Ready, machine.State);
    }

    [TestMethod]
    public void VerackThenVersionBecomesReadyAtomicallyInExactOrder()
    {
        var machine = CreateStartedMachine();
        Span<BsvHandshakeOutput> output = stackalloc BsvHandshakeOutput[3];
        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(BsvHandshakeInput.PeerVerack(), output, out var verackWritten));
        Assert.AreEqual(0, verackWritten);
        Assert.IsTrue(machine.HasPeerVerack);

        output.Fill(new BsvHandshakeOutput((BsvHandshakeOutputKind)byte.MaxValue, ulong.MaxValue));
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Apply(
                BsvHandshakeInput.PeerVersion(MinimumProtocolVersion, PeerNonce),
                output[..2],
                out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.IsFalse(machine.HasPeerVersion);
        AssertFilled(
            output[..2],
            new BsvHandshakeOutput((BsvHandshakeOutputKind)byte.MaxValue, ulong.MaxValue));

        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(
                BsvHandshakeInput.PeerVersion(MinimumProtocolVersion, PeerNonce),
                output,
                out var outputsWritten));
        AssertOutputs(
            output[..outputsWritten],
            (BsvHandshakeOutputKind.SendVerack, 0),
            (BsvHandshakeOutputKind.SendProtoconf, 0),
            (BsvHandshakeOutputKind.BecameReady, 0));
        Assert.AreEqual(BsvHandshakeState.Ready, machine.State);
    }

    [TestMethod]
    public void DuplicateVerackIsIdempotentInNegotiatingAndReady()
    {
        var machine = CreateStartedMachine();
        AssertDoneWithoutOutput(machine, BsvHandshakeInput.PeerVerack());
        AssertDoneWithoutOutput(machine, BsvHandshakeInput.PeerVerack());

        CompleteVersion(machine);
        Assert.AreEqual(BsvHandshakeState.Ready, machine.State);
        AssertDoneWithoutOutput(machine, BsvHandshakeInput.PeerVerack());
        Assert.AreEqual(BsvHandshakeState.Ready, machine.State);
    }

    [TestMethod]
    public void InvalidVersionsTerminateWithAnExactStableReason()
    {
        var self = CreateStartedMachine();
        AssertDoneWithoutOutput(
            self,
            BsvHandshakeInput.PeerVersion(MinimumProtocolVersion, LocalNonce));
        AssertTerminal(self, BsvHandshakeTerminalReason.SelfConnection);

        var obsolete = CreateStartedMachine();
        AssertDoneWithoutOutput(
            obsolete,
            BsvHandshakeInput.PeerVersion(MinimumProtocolVersion - 1, PeerNonce));
        AssertTerminal(obsolete, BsvHandshakeTerminalReason.UnsupportedProtocolVersion);

        var duplicate = CreateStartedMachine();
        CompleteVersion(duplicate);
        AssertDoneWithoutOutput(
            duplicate,
            BsvHandshakeInput.PeerVersion(MinimumProtocolVersion, PeerNonce + 1));
        AssertTerminal(duplicate, BsvHandshakeTerminalReason.DuplicateVersion);
    }

    [TestMethod]
    public void ProtoconfIsOptionalAfterVerackButStrictAboutTimingUniquenessAndFloor()
    {
        var early = CreateStartedMachine();
        AssertDoneWithoutOutput(
            early,
            BsvHandshakeInput.PeerProtoconf(BsvHandshakeStateMachine.MinimumPeerReceivePayloadLength));
        AssertTerminal(early, BsvHandshakeTerminalReason.EarlyProtoconf);

        var insufficient = CreateStartedMachine();
        AssertDoneWithoutOutput(insufficient, BsvHandshakeInput.PeerVerack());
        AssertDoneWithoutOutput(
            insufficient,
            BsvHandshakeInput.PeerProtoconf(BsvHandshakeStateMachine.MinimumPeerReceivePayloadLength));
        AssertTerminal(insufficient, BsvHandshakeTerminalReason.EarlyProtoconf);

        insufficient = CreateStartedMachine();
        CompleteHandshake(insufficient);
        AssertDoneWithoutOutput(
            insufficient,
            BsvHandshakeInput.PeerProtoconf(BsvHandshakeStateMachine.MinimumPeerReceivePayloadLength - 1));
        AssertTerminal(insufficient, BsvHandshakeTerminalReason.InsufficientPeerReceiveLimit);

        var accepted = CreateStartedMachine();
        CompleteHandshake(accepted);
        AssertDoneWithoutOutput(
            accepted,
            BsvHandshakeInput.PeerProtoconf(BsvHandshakeStateMachine.MinimumPeerReceivePayloadLength));
        Assert.IsTrue(accepted.HasPeerProtoconf);
        Assert.AreEqual(
            BsvHandshakeStateMachine.MinimumPeerReceivePayloadLength,
            accepted.AdvertisedPeerMaximumReceivePayloadLength);
        Assert.AreEqual(
            BsvHandshakeStateMachine.MinimumPeerReceivePayloadLength,
            accepted.EffectivePeerMaximumReceivePayloadLength);
        Assert.AreEqual(BsvHandshakeState.Ready, accepted.State);

        AssertDoneWithoutOutput(
            accepted,
            BsvHandshakeInput.PeerProtoconf(BsvHandshakeStateMachine.MinimumPeerReceivePayloadLength + 1));
        AssertTerminal(accepted, BsvHandshakeTerminalReason.DuplicateProtoconf);
    }

    [TestMethod]
    public void ReadyWithoutProtoconfUsesTheNormativeDefaultReceiveLimit()
    {
        var machine = CreateStartedMachine();

        CompleteHandshake(machine);

        Assert.IsFalse(machine.HasPeerProtoconf);
        Assert.AreEqual<uint>(0, machine.AdvertisedPeerMaximumReceivePayloadLength);
        Assert.AreEqual(
            BsvHandshakeStateMachine.DefaultPeerMaximumReceivePayloadLength,
            machine.EffectivePeerMaximumReceivePayloadLength);
    }

    [TestMethod]
    public void PeerPingEchoesDuringNegotiationAndAfterReadyWithoutChangingPhase()
    {
        var machine = CreateStartedMachine();
        AssertSingleOutputIsAtomic(
            machine,
            BsvHandshakeInput.PeerPing(42),
            BsvHandshakeOutputKind.SendPong,
            42);
        Assert.AreEqual(BsvHandshakeState.Negotiating, machine.State);

        CompleteHandshake(machine);
        AssertSingleOutputIsAtomic(
            machine,
            BsvHandshakeInput.PeerPing(43),
            BsvHandshakeOutputKind.SendPong,
            43);
        Assert.AreEqual(BsvHandshakeState.Ready, machine.State);
    }

    [TestMethod]
    public void LocalPingIsReadyOnlySingleFlightAndOnlyMatchingPongAcknowledges()
    {
        var machine = CreateStartedMachine();
        Span<BsvHandshakeOutput> output = stackalloc BsvHandshakeOutput[1];
        Assert.AreEqual(
            OperationStatus.InvalidData,
            machine.TryBeginPing(100, output, out var earlyWritten));
        Assert.AreEqual(0, earlyWritten);

        CompleteHandshake(machine);
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.TryBeginPing(100, Span<BsvHandshakeOutput>.Empty, out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.IsFalse(machine.HasPendingPing);

        Assert.AreEqual(OperationStatus.Done, machine.TryBeginPing(100, output, out var pingWritten));
        AssertOutputs(output[..pingWritten], (BsvHandshakeOutputKind.SendPing, 100));
        Assert.IsTrue(machine.HasPendingPing);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            machine.TryBeginPing(101, output, out var duplicateWritten));
        Assert.AreEqual(0, duplicateWritten);

        AssertDoneWithoutOutput(machine, BsvHandshakeInput.PeerPong(101));
        Assert.IsTrue(machine.HasPendingPing);
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Apply(BsvHandshakeInput.PeerPong(100), Span<BsvHandshakeOutput>.Empty, out shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.IsTrue(machine.HasPendingPing);

        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(BsvHandshakeInput.PeerPong(100), output, out var pongWritten));
        AssertOutputs(output[..pongWritten], (BsvHandshakeOutputKind.PingAcknowledged, 100));
        Assert.IsFalse(machine.HasPendingPing);

        AssertDoneWithoutOutput(machine, BsvHandshakeInput.PeerPong(100));
    }

    [TestMethod]
    public void RejectBeforeReadyTerminatesButReadyRejectIsForwardedAtomically()
    {
        var negotiating = CreateStartedMachine();
        AssertDoneWithoutOutput(negotiating, BsvHandshakeInput.PeerReject());
        AssertTerminal(negotiating, BsvHandshakeTerminalReason.RejectBeforeReady);

        var ready = CreateStartedMachine();
        CompleteHandshake(ready);
        AssertSingleOutputIsAtomic(
            ready,
            BsvHandshakeInput.PeerReject(),
            BsvHandshakeOutputKind.ForwardReject,
            0);
        Assert.AreEqual(BsvHandshakeState.Ready, ready.State);
    }

    [TestMethod]
    public void ExplicitFailuresTerminateAndTerminalIsIdempotent()
    {
        var wire = CreateStartedMachine();
        AssertDoneWithoutOutput(wire, BsvHandshakeInput.WireViolation());
        AssertTerminal(wire, BsvHandshakeTerminalReason.WireViolation);

        Span<BsvHandshakeOutput> output = stackalloc BsvHandshakeOutput[3];
        Assert.AreEqual(
            OperationStatus.Done,
            wire.Apply(BsvHandshakeInput.ExternalFailure(), output, out var repeatedWritten));
        Assert.AreEqual(0, repeatedWritten);
        AssertTerminal(wire, BsvHandshakeTerminalReason.WireViolation);

        var external = CreateStartedMachine();
        CompleteHandshake(external);
        AssertDoneWithoutOutput(external, BsvHandshakeInput.ExternalFailure());
        AssertTerminal(external, BsvHandshakeTerminalReason.ExternalFailure);
    }

    [TestMethod]
    public void InvalidCallsBeforeStartDoNotMutateCreatedState()
    {
        var machine = CreateMachine();
        Span<BsvHandshakeOutput> output = stackalloc BsvHandshakeOutput[3];
        Assert.AreEqual(
            OperationStatus.InvalidData,
            machine.Apply(BsvHandshakeInput.PeerVerack(), output, out var outputsWritten));
        Assert.AreEqual(0, outputsWritten);
        Assert.AreEqual(BsvHandshakeState.Created, machine.State);

        Assert.AreEqual(
            OperationStatus.InvalidData,
            machine.Apply(default, output, out outputsWritten));
        Assert.AreEqual(0, outputsWritten);
        Assert.AreEqual(BsvHandshakeState.Created, machine.State);
    }

    [TestMethod]
    public void TransitionHotLoopAllocatesNothingAfterWarmup()
    {
        var machine = CreateStartedMachine();
        Span<BsvHandshakeOutput> output = stackalloc BsvHandshakeOutput[1];

        for (var index = 0; index < 1_000; index++)
        {
            Assert.AreEqual(
                OperationStatus.Done,
                machine.Apply(BsvHandshakeInput.PeerPing((ulong)index), output, out _));
        }

        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var index = 0; index < 10_000; index++)
        {
            var status = machine.Apply(BsvHandshakeInput.PeerPing((ulong)index), output, out var outputsWritten);
            if (status != OperationStatus.Done || outputsWritten != 1)
            {
                Assert.Fail("Ping transition failed inside the allocation probe.");
            }
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.AreEqual(0L, allocated);
    }

    [TestMethod]
    public void MinimumVersionMustBeAnExplicitPositiveProfileChoice()
    {
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => new BsvHandshakeStateMachine(0));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => new BsvHandshakeStateMachine(-1));
        Assert.AreEqual(MinimumProtocolVersion, CreateMachine().MinimumPeerProtocolVersion);
    }

    private static BsvHandshakeStateMachine CreateMachine() => new(MinimumProtocolVersion);

    private static BsvHandshakeStateMachine CreateStartedMachine()
    {
        var machine = CreateMachine();
        Span<BsvHandshakeOutput> output = stackalloc BsvHandshakeOutput[1];
        Assert.AreEqual(OperationStatus.Done, machine.Start(LocalNonce, output, out _));
        return machine;
    }

    private static void CompleteVersion(BsvHandshakeStateMachine machine)
    {
        Span<BsvHandshakeOutput> output = stackalloc BsvHandshakeOutput[3];
        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(
                BsvHandshakeInput.PeerVersion(MinimumProtocolVersion, PeerNonce),
                output,
                out _));
    }

    private static void CompleteHandshake(BsvHandshakeStateMachine machine)
    {
        CompleteVersion(machine);
        Span<BsvHandshakeOutput> output = stackalloc BsvHandshakeOutput[1];
        Assert.AreEqual(
            OperationStatus.Done,
            machine.Apply(BsvHandshakeInput.PeerVerack(), output, out _));
        Assert.AreEqual(BsvHandshakeState.Ready, machine.State);
    }

    private static void AssertSingleOutputIsAtomic(
        BsvHandshakeStateMachine machine,
        BsvHandshakeInput input,
        BsvHandshakeOutputKind expectedKind,
        ulong expectedValue)
    {
        var state = machine.State;
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            machine.Apply(input, Span<BsvHandshakeOutput>.Empty, out var shortWritten));
        Assert.AreEqual(0, shortWritten);
        Assert.AreEqual(state, machine.State);

        Span<BsvHandshakeOutput> output = stackalloc BsvHandshakeOutput[1];
        Assert.AreEqual(OperationStatus.Done, machine.Apply(input, output, out var outputsWritten));
        AssertOutputs(output[..outputsWritten], (expectedKind, expectedValue));
    }

    private static void AssertDoneWithoutOutput(
        BsvHandshakeStateMachine machine,
        BsvHandshakeInput input)
    {
        Span<BsvHandshakeOutput> output = stackalloc BsvHandshakeOutput[3];
        output.Fill(new BsvHandshakeOutput((BsvHandshakeOutputKind)byte.MaxValue, ulong.MaxValue));
        Assert.AreEqual(OperationStatus.Done, machine.Apply(input, output, out var outputsWritten));
        Assert.AreEqual(0, outputsWritten);
        AssertFilled(output, new BsvHandshakeOutput((BsvHandshakeOutputKind)byte.MaxValue, ulong.MaxValue));
    }

    private static void AssertTerminal(
        BsvHandshakeStateMachine machine,
        BsvHandshakeTerminalReason expectedReason)
    {
        Assert.AreEqual(BsvHandshakeState.Terminal, machine.State);
        Assert.AreEqual(expectedReason, machine.TerminalReason);
        Assert.IsFalse(machine.HasPendingPing);
    }

    private static void AssertOutputs(
        ReadOnlySpan<BsvHandshakeOutput> actual,
        params (BsvHandshakeOutputKind Kind, ulong Value)[] expected)
    {
        Assert.AreEqual(expected.Length, actual.Length);
        for (var index = 0; index < expected.Length; index++)
        {
            Assert.AreEqual(expected[index].Kind, actual[index].Kind, $"output {index}");
            Assert.AreEqual(expected[index].Value, actual[index].Value, $"output {index}");
        }
    }

    private static void AssertFilled(
        ReadOnlySpan<BsvHandshakeOutput> actual,
        BsvHandshakeOutput expected)
    {
        for (var index = 0; index < actual.Length; index++)
        {
            Assert.AreEqual(expected, actual[index], $"output {index}");
        }
    }
}
