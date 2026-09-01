using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Messages;
using Staffetta.Core.Protocol.Relay;
using Staffetta.Core.Protocol.Sessions;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Tests.Protocol.Sessions;

[TestClass]
public sealed class BsvPeerSessionEgressPlannerTests
{
    private static ReadOnlySpan<byte> Magic => [0xe3, 0xe1, 0xf3, 0xe8];

    [TestMethod]
    public void FixedSendIntentsMapToExactBasicFramesAndCompletions()
    {
        const ulong nonce = 0x0102_0304_0506_0708;
        var transactionId = Hash256.DoubleSha256("correlation"u8);

        using (var planner = CreatePlanner())
        {
            var version = CreateVersion(nonce);
            Assert.AreEqual(
                OperationStatus.Done,
                planner.PlanVersion(
                    new BsvHandshakeOutput(BsvHandshakeOutputKind.SendVersion, nonce),
                    version,
                    ulong.MaxValue));
            Span<byte> expected = stackalloc byte[VersionPayloadCodec.MaximumPayloadLength];
            Assert.AreEqual(OperationStatus.Done, VersionPayloadCodec.TryWrite(expected, version, out var length));
            AssertFrame(planner, "version"u8, expected[..length], BsvPeerSessionSendKind.Version, nonce);
        }

        AssertHandshakeFrame(
            new BsvHandshakeOutput(BsvHandshakeOutputKind.SendVerack),
            "verack"u8,
            [],
            BsvPeerSessionSendKind.Verack);

        Span<byte> noncePayload = stackalloc byte[ModernPingPongPayloadCodec.EncodedLength];
        _ = ModernPingPongPayloadCodec.TryWrite(noncePayload, nonce, out _);
        AssertHandshakeFrame(
            new BsvHandshakeOutput(BsvHandshakeOutputKind.SendPong, nonce),
            "pong"u8,
            noncePayload,
            BsvPeerSessionSendKind.Pong);
        AssertHandshakeFrame(
            new BsvHandshakeOutput(BsvHandshakeOutputKind.SendPing, nonce),
            "ping"u8,
            noncePayload,
            BsvPeerSessionSendKind.Ping);

        using (var planner = CreatePlanner())
        {
            Assert.AreEqual(
                OperationStatus.Done,
                planner.PlanProtoconf(
                    new BsvHandshakeOutput(BsvHandshakeOutputKind.SendProtoconf),
                    128 * 1024 * 1024,
                    "Default"u8,
                    includeStreamPolicies: true,
                    ulong.MaxValue));
            Span<byte> expected = stackalloc byte[ProtoconfPayloadCodec.MaximumStreamPoliciesLength + 8];
            Assert.AreEqual(
                OperationStatus.Done,
                ProtoconfPayloadCodec.TryWrite(
                    expected,
                    128 * 1024 * 1024,
                    "Default"u8,
                    includeStreamPolicies: true,
                    out var length));
            AssertFrame(planner, "protoconf"u8, expected[..length], BsvPeerSessionSendKind.Protoconf);
        }

        Span<InventoryVector> vector = stackalloc InventoryVector[1];
        vector[0] = new InventoryVector(1, transactionId);
        Span<byte> inventoryPayload = stackalloc byte[37];
        Assert.AreEqual(
            OperationStatus.Done,
            InventoryPayloadCodec.TryWrite(vector, inventoryPayload, 37, out var inventoryLength));

        using (var planner = CreatePlanner())
        {
            Assert.AreEqual(
                OperationStatus.Done,
                planner.PlanBroadcast(
                    new BsvTransactionBroadcastOutput(
                        BsvTransactionBroadcastOutputKind.SendInventory,
                        transactionId),
                    ulong.MaxValue,
                    out var disposition));
            Assert.AreEqual(BsvPeerSessionOutputDisposition.Send, disposition);
            AssertFrame(
                planner,
                "inv"u8,
                inventoryPayload[..inventoryLength],
                BsvPeerSessionSendKind.Inventory,
                transactionId: transactionId,
                commitKind: BsvPeerSessionRelayWriteCommitKind.Inventory);
        }

        using (var planner = CreatePlanner())
        {
            Assert.AreEqual(
                OperationStatus.Done,
                planner.PlanFetch(
                    new BsvTransactionFetchOutput(BsvTransactionFetchOutputKind.SendGetData, transactionId),
                    ulong.MaxValue,
                    out var disposition));
            Assert.AreEqual(BsvPeerSessionOutputDisposition.Send, disposition);
            AssertFrame(
                planner,
                "getdata"u8,
                inventoryPayload[..inventoryLength],
                BsvPeerSessionSendKind.GetData,
                transactionId: transactionId,
                commitKind: BsvPeerSessionRelayWriteCommitKind.GetData);
        }
    }

    [TestMethod]
    public void FactsAreIdentifiedWithoutCreatingWireSegments()
    {
        var transactionId = Hash256.DoubleSha256("fact"u8);
        foreach (var output in new[]
                 {
                     new BsvHandshakeOutput(BsvHandshakeOutputKind.BecameReady),
                     new BsvHandshakeOutput(BsvHandshakeOutputKind.PingAcknowledged, 1),
                     new BsvHandshakeOutput(BsvHandshakeOutputKind.ForwardReject),
                 })
        {
            using var planner = CreatePlanner();
            Assert.AreEqual(
                OperationStatus.Done,
                planner.PlanHandshake(output, ulong.MaxValue, out var disposition));
            Assert.AreEqual(BsvPeerSessionOutputDisposition.Fact, disposition);
            Assert.IsTrue(planner.PendingSegment.IsEmpty);
            Assert.IsFalse(planner.TryPeekCompletion(out _));
        }

        foreach (var kind in new[]
                 {
                     BsvTransactionBroadcastOutputKind.Announced,
                     BsvTransactionBroadcastOutputKind.RequestedByPeer,
                     BsvTransactionBroadcastOutputKind.SentToPeer,
                     BsvTransactionBroadcastOutputKind.ObservedFromPeer,
                     BsvTransactionBroadcastOutputKind.Rejected,
                 })
        {
            using var planner = CreatePlanner();
            Assert.AreEqual(
                OperationStatus.Done,
                planner.PlanBroadcast(
                    new BsvTransactionBroadcastOutput(kind, transactionId),
                    ulong.MaxValue,
                    out var disposition));
            Assert.AreEqual(BsvPeerSessionOutputDisposition.Fact, disposition);
            Assert.IsTrue(planner.PendingSegment.IsEmpty);
        }

        foreach (var kind in new[]
                 {
                     BsvTransactionFetchOutputKind.Requested,
                     BsvTransactionFetchOutputKind.UnexpectedTransaction,
                     BsvTransactionFetchOutputKind.Received,
                     BsvTransactionFetchOutputKind.NotFound,
                 })
        {
            using var planner = CreatePlanner();
            Assert.AreEqual(
                OperationStatus.Done,
                planner.PlanFetch(
                    new BsvTransactionFetchOutput(kind, transactionId),
                    ulong.MaxValue,
                    out var disposition));
            Assert.AreEqual(BsvPeerSessionOutputDisposition.Fact, disposition);
            Assert.IsTrue(planner.PendingSegment.IsEmpty);
        }
    }

    [TestMethod]
    public void TransactionChunksAreBorrowedAndCompletionWaitsForExactAcknowledgedHash()
    {
        byte[] transaction = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        var transactionId = Hash256.DoubleSha256(transaction);
        using var planner = CreatePlanner();

        Assert.AreEqual(
            OperationStatus.Done,
            planner.PlanTransaction(
                new BsvTransactionBroadcastOutput(
                    BsvTransactionBroadcastOutputKind.SendTransaction,
                    transactionId),
                (ulong)transaction.Length,
                transactionId,
                ulong.MaxValue));

        var wire = new List<byte>();
        DrainPendingOneByte(planner, wire);
        Assert.IsFalse(planner.TryPeekCompletion(out _));

        Assert.AreEqual(OperationStatus.Done, planner.ProvideTransactionChunk(transaction.AsMemory(0, 3)));
        DrainPendingOneByte(planner, wire);
        Assert.IsFalse(planner.TryPeekCompletion(out _));
        Assert.AreEqual(OperationStatus.Done, planner.ProvideTransactionChunk(transaction.AsMemory(3)));
        DrainPendingOneByte(planner, wire);

        Assert.IsTrue(planner.TryPeekCompletion(out var completion));
        Assert.AreEqual(BsvPeerSessionSendKind.Transaction, completion.SendKind);
        Assert.AreEqual(BsvPeerSessionRelayWriteCommitKind.Transaction, completion.RelayWriteCommitKind);
        Assert.AreEqual(transactionId, completion.TransactionId);
        Assert.AreEqual(OperationStatus.Done, planner.EndTransactionPayload());
        Assert.AreEqual(OperationStatus.Done, planner.CommitCompletion());

        var bytes = wire.ToArray();
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryParse(bytes, Magic, ulong.MaxValue, out var header, out var headerLength));
        Assert.IsTrue(header.Command.Equals("tx"u8));
        Assert.AreEqual(MessageHeaderFormat.Basic, header.Format);
        Assert.AreEqual(MessageChecksum.Compute(transaction), header.PayloadChecksum);
        CollectionAssert.AreEqual(transaction, bytes[headerLength..]);
    }

    [TestMethod]
    public void TransactionHashMismatchAndShortOrOverPayloadAreTerminal()
    {
        byte[] payload = [1, 2, 3];
        var actual = Hash256.DoubleSha256(payload);
        var wrong = Hash256.DoubleSha256("wrong"u8);
        using (var planner = CreatePlanner())
        {
            Assert.AreEqual(
                OperationStatus.Done,
                planner.PlanTransaction(
                    new BsvTransactionBroadcastOutput(BsvTransactionBroadcastOutputKind.SendTransaction, wrong),
                    3,
                    wrong,
                    ulong.MaxValue));
            DrainPendingOneByte(planner, null);
            Assert.AreEqual(OperationStatus.Done, planner.ProvideTransactionChunk(payload));
            Assert.AreEqual(OperationStatus.InvalidData, DrainPendingOneByte(planner, null));
            Assert.AreEqual(BsvPeerSessionEgressState.Faulted, planner.State);
            Assert.IsFalse(planner.TryPeekCompletion(out _));
        }

        using (var planner = CreatePlanner())
        {
            Assert.AreEqual(
                OperationStatus.Done,
                planner.PlanTransaction(
                    new BsvTransactionBroadcastOutput(BsvTransactionBroadcastOutputKind.SendTransaction, actual),
                    4,
                    actual,
                    ulong.MaxValue));
            DrainPendingOneByte(planner, null);
            Assert.AreEqual(OperationStatus.Done, planner.ProvideTransactionChunk(payload));
            DrainPendingOneByte(planner, null);
            Assert.AreEqual(OperationStatus.InvalidData, planner.EndTransactionPayload());
            Assert.AreEqual(BsvPeerSessionEgressState.Faulted, planner.State);
        }

        using (var planner = CreatePlanner())
        {
            Assert.AreEqual(
                OperationStatus.Done,
                planner.PlanTransaction(
                    new BsvTransactionBroadcastOutput(BsvTransactionBroadcastOutputKind.SendTransaction, actual),
                    2,
                    actual,
                    ulong.MaxValue));
            DrainPendingOneByte(planner, null);
            Assert.AreEqual(OperationStatus.InvalidData, planner.ProvideTransactionChunk(payload));
            Assert.AreEqual(BsvPeerSessionEgressState.Faulted, planner.State);
        }
    }

    [TestMethod]
    public void BasicAndExtendedTransactionBoundaryUseExactHeaderFormatsWithoutLargeAllocation()
    {
        var transactionId = Hash256.DoubleSha256("boundary"u8);
        using (var basic = CreatePlanner())
        {
            Assert.AreEqual(
                OperationStatus.Done,
                basic.PlanTransaction(
                    new BsvTransactionBroadcastOutput(
                        BsvTransactionBroadcastOutputKind.SendTransaction,
                        transactionId),
                    uint.MaxValue,
                    transactionId,
                    ulong.MaxValue));
            Assert.AreEqual(MessageHeaderCodec.BasicHeaderLength, basic.PendingSegment.Length);
            Assert.AreEqual(OperationStatus.Done, basic.Abort());
        }

        using (var extended = CreatePlanner())
        {
            Assert.AreEqual(
                OperationStatus.Done,
                extended.PlanTransaction(
                    new BsvTransactionBroadcastOutput(
                        BsvTransactionBroadcastOutputKind.SendTransaction,
                        transactionId),
                    (ulong)uint.MaxValue + 1,
                    transactionId,
                    ulong.MaxValue));
            var headerBytes = extended.PendingSegment.Memory.ToArray();
            Assert.AreEqual(MessageHeaderCodec.ExtendedHeaderLength, headerBytes.Length);
            Assert.AreEqual(
                OperationStatus.Done,
                MessageHeaderCodec.TryParse(
                    headerBytes,
                    Magic,
                    ulong.MaxValue,
                    out var header,
                    out var bytesConsumed));
            Assert.AreEqual(MessageHeaderCodec.ExtendedHeaderLength, bytesConsumed);
            Assert.AreEqual(MessageHeaderFormat.Extended, header.Format);
            Assert.AreEqual((ulong)uint.MaxValue + 1, header.PayloadLength);
            Assert.IsTrue(header.Command.Equals("tx"u8));
            Assert.AreEqual(OperationStatus.Done, extended.Acknowledge(extended.PendingSegment, headerBytes.Length));
            byte[] repeatedChunk = [0xaa, 0xbb, 0xcc];
            Assert.AreEqual(OperationStatus.Done, extended.ProvideTransactionChunk(repeatedChunk));
            Assert.AreEqual(OperationStatus.Done, extended.Acknowledge(extended.PendingSegment, repeatedChunk.Length));
            Assert.AreEqual(OperationStatus.Done, extended.Abort());
            Assert.AreEqual(BsvPeerSessionEgressState.Aborted, extended.State);
        }
    }

    [TestMethod]
    public void StaleLeaseWrongOutputAndPrematureReuseFaultWithoutCompletion()
    {
        using (var planner = CreatePlanner())
        {
            Assert.AreEqual(
                OperationStatus.Done,
                planner.PlanHandshake(
                    new BsvHandshakeOutput(BsvHandshakeOutputKind.SendPing, 1),
                    ulong.MaxValue,
                    out _));
            var stale = planner.PendingSegment;
            Assert.AreEqual(OperationStatus.Done, planner.Acknowledge(stale, 1));
            Assert.AreEqual(OperationStatus.InvalidData, planner.Acknowledge(stale, 1));
            Assert.AreEqual(BsvPeerSessionEgressState.Faulted, planner.State);
            Assert.IsFalse(planner.TryPeekCompletion(out _));
        }

        using (var planner = CreatePlanner())
        {
            Assert.AreEqual(
                OperationStatus.InvalidData,
                planner.PlanHandshake(
                    new BsvHandshakeOutput(BsvHandshakeOutputKind.SendVersion, 1),
                    ulong.MaxValue,
                    out _));
            Assert.AreEqual(BsvPeerSessionEgressState.Faulted, planner.State);
        }

        using (var planner = CreatePlanner())
        {
            Assert.AreEqual(
                OperationStatus.Done,
                planner.PlanHandshake(
                    new BsvHandshakeOutput(BsvHandshakeOutputKind.SendVerack),
                    ulong.MaxValue,
                    out _));
            Assert.AreEqual(
                OperationStatus.InvalidData,
                planner.PlanHandshake(
                    new BsvHandshakeOutput(BsvHandshakeOutputKind.SendVerack),
                    ulong.MaxValue,
                    out _));
            Assert.AreEqual(BsvPeerSessionEgressState.Faulted, planner.State);
        }
    }

    [TestMethod]
    public void NegotiatedMaximumAndZeroValueOutputsAreEnforced()
    {
        using (var fixedFrame = CreatePlanner())
        {
            Assert.AreEqual(
                OperationStatus.InvalidData,
                fixedFrame.PlanHandshake(
                    new BsvHandshakeOutput(BsvHandshakeOutputKind.SendPing, 1),
                    maximumOutboundPayloadLength: 7,
                    out _));
            Assert.AreEqual(BsvPeerSessionEgressState.Faulted, fixedFrame.State);
        }

        var transactionId = Hash256.DoubleSha256([1, 2, 3]);
        using (var transaction = CreatePlanner())
        {
            Assert.AreEqual(
                OperationStatus.InvalidData,
                transaction.PlanTransaction(
                    new BsvTransactionBroadcastOutput(
                        BsvTransactionBroadcastOutputKind.SendTransaction,
                        transactionId),
                    3,
                    transactionId,
                    maximumOutboundPayloadLength: 2));
            Assert.AreEqual(BsvPeerSessionEgressState.Faulted, transaction.State);
        }

        using (var verack = CreatePlanner())
        {
            Assert.AreEqual(
                OperationStatus.InvalidData,
                verack.PlanHandshake(
                    new BsvHandshakeOutput(BsvHandshakeOutputKind.SendVerack, 1),
                    ulong.MaxValue,
                    out _));
        }

        using (var protoconf = CreatePlanner())
        {
            Assert.AreEqual(
                OperationStatus.InvalidData,
                protoconf.PlanProtoconf(
                    new BsvHandshakeOutput(BsvHandshakeOutputKind.SendProtoconf, 1),
                    1,
                    default,
                    includeStreamPolicies: false,
                    ulong.MaxValue));
        }
    }

    [TestMethod]
    public void CompletionIsGenerationBoundAndDestinationBackpressurePreservesRetry()
    {
        var owner = new RecordingCompletionOwner
        {
            NextStatus = OperationStatus.DestinationTooSmall,
        };
        using var planner = CreatePlanner(owner);
        Assert.AreEqual(
            OperationStatus.Done,
            planner.PlanHandshake(
                new BsvHandshakeOutput(BsvHandshakeOutputKind.SendVerack),
                ulong.MaxValue,
                out _));
        DrainPendingOneByte(planner, null);
        Assert.IsTrue(planner.TryPeekCompletion(out var first));
        Assert.AreEqual(OperationStatus.DestinationTooSmall, planner.CommitCompletion());
        Assert.IsTrue(planner.TryPeekCompletion(out var retry));
        Assert.AreEqual(first, retry);
        owner.NextStatus = OperationStatus.Done;
        Assert.AreEqual(OperationStatus.Done, planner.CommitCompletion());
        Assert.IsFalse(planner.TryPeekCompletion(out _));
        Assert.AreEqual(
            OperationStatus.Done,
            planner.PlanHandshake(
                new BsvHandshakeOutput(BsvHandshakeOutputKind.SendVerack),
                ulong.MaxValue,
                out _));
        DrainPendingOneByte(planner, null);
        Assert.IsTrue(planner.TryPeekCompletion(out var second));
        Assert.AreNotEqual(first.PlanId, second.PlanId);
        Assert.IsTrue(second.PlanId > first.PlanId);
    }

    [TestMethod]
    public void WarmFixedFrameCyclesHaveNoPerCycleManagedAllocation()
    {
        var transactionId = Hash256.DoubleSha256("allocation"u8);
        using var planner = CreatePlanner();
        for (var index = 0; index < 32; index++)
        {
            RunInventoryCycle(planner, transactionId);
        }

        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var index = 0; index < 1_024; index++)
        {
            RunInventoryCycle(planner, transactionId);
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.AreEqual(0L, allocated);
    }

    [TestMethod]
    public void TransactionBorrowedChunkPartialAcknowledgementsAllocateNothing()
    {
        var payload = new byte[4_096];
        for (var index = 0; index < payload.Length; index++)
        {
            payload[index] = (byte)index;
        }

        var transactionId = Hash256.DoubleSha256(payload);
        using var planner = CreatePlanner();
        Assert.AreEqual(
            OperationStatus.Done,
            planner.PlanTransaction(
                new BsvTransactionBroadcastOutput(
                    BsvTransactionBroadcastOutputKind.SendTransaction,
                    transactionId),
                (ulong)payload.Length,
                transactionId,
                ulong.MaxValue));
        Assert.AreEqual(
            OperationStatus.Done,
            planner.Acknowledge(planner.PendingSegment, planner.PendingSegment.Length));
        Assert.AreEqual(OperationStatus.Done, planner.ProvideTransactionChunk(payload));
        Assert.AreEqual(payload.AsMemory(), planner.PendingSegment.Memory);
        Assert.AreEqual(OperationStatus.Done, planner.Acknowledge(planner.PendingSegment, 1));

        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var index = 1; index < payload.Length - 1; index++)
        {
            Assert.AreEqual(OperationStatus.Done, planner.Acknowledge(planner.PendingSegment, 1));
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.AreEqual(0L, allocated);
        Assert.AreEqual(OperationStatus.Done, planner.Acknowledge(planner.PendingSegment, 1));
        Assert.IsTrue(planner.TryPeekCompletion(out _));
        Assert.AreEqual(OperationStatus.Done, planner.CommitCompletion());
    }

    private static void AssertHandshakeFrame(
        BsvHandshakeOutput output,
        ReadOnlySpan<byte> command,
        ReadOnlySpan<byte> expectedPayload,
        BsvPeerSessionSendKind sendKind)
    {
        using var planner = CreatePlanner();
        Assert.AreEqual(
            OperationStatus.Done,
            planner.PlanHandshake(output, ulong.MaxValue, out var disposition));
        Assert.AreEqual(BsvPeerSessionOutputDisposition.Send, disposition);
        AssertFrame(planner, command, expectedPayload, sendKind, output.Value);
    }

    private static void AssertFrame(
        BsvPeerSessionEgressPlanner planner,
        ReadOnlySpan<byte> command,
        ReadOnlySpan<byte> expectedPayload,
        BsvPeerSessionSendKind sendKind,
        ulong value = 0,
        Hash256 transactionId = default,
        BsvPeerSessionRelayWriteCommitKind commitKind = BsvPeerSessionRelayWriteCommitKind.None)
    {
        var wire = new List<byte>();
        Assert.AreEqual(OperationStatus.Done, DrainPendingOneByte(planner, wire));
        var encoded = wire.ToArray();
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryParse(
                encoded,
                Magic,
                ulong.MaxValue,
                out var header,
                out var headerLength));
        Assert.AreEqual(MessageHeaderFormat.Basic, header.Format);
        Assert.IsTrue(header.Command.Equals(command));
        Assert.AreEqual((ulong)expectedPayload.Length, header.PayloadLength);
        Assert.AreEqual(MessageChecksum.Compute(expectedPayload), header.PayloadChecksum);
        CollectionAssert.AreEqual(expectedPayload.ToArray(), encoded[headerLength..]);
        Assert.IsTrue(planner.TryPeekCompletion(out var completion));
        Assert.AreEqual(OperationStatus.Done, planner.CommitCompletion());
        Assert.AreEqual(sendKind, completion.SendKind);
        Assert.AreEqual(commitKind, completion.RelayWriteCommitKind);
        Assert.AreEqual(transactionId, completion.TransactionId);
        Assert.AreEqual(value, completion.Value);
    }

    private static OperationStatus DrainPendingOneByte(
        BsvPeerSessionEgressPlanner planner,
        List<byte>? destination)
    {
        while (!planner.PendingSegment.IsEmpty)
        {
            var pending = planner.PendingSegment;
            destination?.Add(pending.Span[0]);
            var status = planner.Acknowledge(pending, 1);
            if (status != OperationStatus.Done)
            {
                return status;
            }
        }

        return OperationStatus.Done;
    }

    private static void RunInventoryCycle(
        BsvPeerSessionEgressPlanner planner,
        Hash256 transactionId)
    {
        var status = planner.PlanBroadcast(
            new BsvTransactionBroadcastOutput(
                BsvTransactionBroadcastOutputKind.SendInventory,
                transactionId),
            ulong.MaxValue,
            out _);
        while (status == OperationStatus.Done && !planner.PendingSegment.IsEmpty)
        {
            var pending = planner.PendingSegment;
            status = planner.Acknowledge(pending, pending.Length);
        }

        if (status == OperationStatus.Done)
        {
            status = planner.TryPeekCompletion(out _)
                ? planner.CommitCompletion()
                : OperationStatus.InvalidData;
        }

        Assert.AreEqual(OperationStatus.Done, status);
    }

    private static BsvPeerSessionEgressPlanner CreatePlanner(
        RecordingCompletionOwner? owner = null) =>
        new(Magic, owner ?? new RecordingCompletionOwner());

    private static VersionPayload CreateVersion(ulong nonce)
    {
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [127, 0, 0, 1], 8333, out var address));
        return new VersionPayload(
            VersionPayloadCodec.CurrentProtocolVersion,
            services: 1,
            timestampUnixSeconds: 1_700_000_000,
            address,
            address,
            nonce,
            "/staffetta/"u8,
            startHeight: 900_000,
            relay: true);
    }

    private sealed class RecordingCompletionOwner : IBsvPeerSessionEgressCompletionOwner
    {
        internal OperationStatus NextStatus { get; set; } = OperationStatus.Done;

        public OperationStatus ApplyEgressCompletion(
            in BsvPeerSessionEgressCompletion completion) => NextStatus;
    }
}
