using System.Buffers;
using System.Buffers.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Messages;
using Staffetta.Core.Protocol.Sessions;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Tests.Protocol.Sessions;

[TestClass]
public sealed class BsvPeerObservationSessionTests
{
    private static ReadOnlySpan<byte> Magic => [0xe3, 0xe1, 0xf3, 0xe8];

    [TestMethod]
    public void PublicDriverHandshakesAndRequestsArbitraryTransactionWithoutInventingInventory()
    {
        using var session = Ready();
        var target = Hash256.DoubleSha256("arbitrary-request"u8);
        Assert.AreEqual(OperationStatus.Done, session.RequestTransaction(target));
        Assert.IsFalse(session.HasPendingInventory);
        Assert.AreEqual(OperationStatus.DestinationTooSmall, session.RequestTransaction(target));
        var frame = DrainWrites(session);
        Assert.IsTrue(frame.AsSpan(4, 7).SequenceEqual("getdata"u8));
        Assert.AreEqual(37u, BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(16)));
        Assert.AreEqual(1, frame[24]);
        Assert.AreEqual(1u, BinaryPrimitives.ReadUInt32LittleEndian(frame.AsSpan(25)));
        Span<byte> hash = stackalloc byte[32];
        _ = target.TryCopyWireBytesTo(hash, out _);
        Assert.IsTrue(frame.AsSpan(29).SequenceEqual(hash));
        Assert.IsFalse(session.HasPendingInventory);

        Assert.AreEqual(OperationStatus.Done, session.RequestHeaders([target]));
        frame = DrainWrites(session);
        Assert.IsTrue(frame.AsSpan(4, 10).SequenceEqual("getheaders"u8));
        Assert.AreEqual(70016, BinaryPrimitives.ReadInt32LittleEndian(frame.AsSpan(24)));
        Assert.AreEqual(1, frame[28]);
        Assert.IsTrue(frame.AsSpan(29, 32).SequenceEqual(hash));
    }

    [TestMethod]
    public void GenericInventoryIsProvisionalUntilChecksumAndCannotBeOverwritten()
    {
        var txid = Hash256.DoubleSha256("announced"u8);
        InventoryVector[] inventory = [new(1, txid), new(2, txid), new(99, txid)];
        var payload = new byte[109];
        Assert.AreEqual(OperationStatus.Done, InventoryPayloadCodec.TryWrite(inventory, payload, 109, out _));
        var frame = Frame("inv"u8, payload);
        for (var split = 1; split < frame.Length; split++)
        {
            using var session = Ready();
            Assert.AreEqual(OperationStatus.NeedMoreData, session.Consume(frame.AsSpan(0, split), out var used));
            Assert.AreEqual(split, used);
            Assert.AreEqual(0, session.PendingInventoryCount);
            Assert.IsFalse(session.HasPendingInventory);
            Assert.AreEqual(OperationStatus.Done, session.Consume(frame.AsSpan(split), out _));
            Assert.AreEqual(3, session.PendingInventoryCount);
            Assert.AreEqual(OperationStatus.DestinationTooSmall, session.Consume(frame, out used));
            Assert.AreEqual(0, used);
            Assert.AreEqual(OperationStatus.DestinationTooSmall, session.DrainInventory(new InventoryVector[2], out used));
            Assert.AreEqual(0, used);
            var actual = new InventoryVector[3];
            Assert.AreEqual(OperationStatus.Done, session.DrainInventory(actual, out used));
            CollectionAssert.AreEqual(inventory, actual);
            Assert.AreEqual(3, used);
            Assert.IsFalse(session.HasPendingInventory);
        }

        using var corrupt = Ready();
        frame[20] ^= 1;
        Assert.AreEqual(OperationStatus.InvalidData, corrupt.Consume(frame, out _));
        Assert.IsFalse(corrupt.HasPendingInventory);
        Assert.AreEqual(0, corrupt.PendingInventoryCount);
    }

    [TestMethod]
    public void NotFoundPreservesAllVectorsOnlyAfterValidationAndUntilEntireBatchDrains()
    {
        var requested = Hash256.DoubleSha256("requested"u8);
        var other = Hash256.DoubleSha256("other"u8);
        InventoryVector[] vectors = [new(1, requested), new(1, other), new(2, requested), new(99, other)];
        var payload = new byte[145];
        Assert.AreEqual(OperationStatus.Done, InventoryPayloadCodec.TryWrite(vectors, payload, 145, out _));
        var frame = Frame("notfound"u8, payload);
        for (var split = 1; split < frame.Length; split++)
        {
            using var session = Ready(maximumInventoryCount: 4);
            Assert.AreEqual(OperationStatus.Done, session.RequestTransaction(requested));
            _ = DrainWrites(session);
            Assert.AreEqual(OperationStatus.NeedMoreData, session.Consume(frame.AsSpan(0, split), out var used));
            Assert.AreEqual(split, used);
            Assert.IsFalse(session.HasPendingNotFound);
            Assert.AreEqual(0, session.PendingNotFoundCount);
            Assert.AreEqual(OperationStatus.Done, session.DrainNotFound([], out var count));
            Assert.AreEqual(0, count);
            Assert.AreEqual(OperationStatus.Done, session.Consume(frame.AsSpan(split), out used));
            Assert.AreEqual(frame.Length - split, used);
            Assert.IsTrue(session.HasPendingNotFound);
            Assert.AreEqual(4, session.PendingNotFoundCount);
            Assert.IsFalse(session.HasPendingInventory);
            Assert.AreEqual(0, session.PendingInventoryCount);
            Assert.AreEqual(OperationStatus.Done, session.DrainInventory([], out count));
            Assert.AreEqual(0, count);
            Assert.IsTrue(session.HasPendingNotFound);
            Assert.AreEqual(OperationStatus.DestinationTooSmall, session.Consume(Frame("inv"u8, [0]), out used));
            Assert.AreEqual(0, used);
            Assert.AreEqual(OperationStatus.DestinationTooSmall, session.CompleteEndOfInput());
            Assert.AreEqual(OperationStatus.DestinationTooSmall, session.DrainNotFound(new InventoryVector[3], out count));
            Assert.AreEqual(0, count);
            Assert.AreEqual(4, session.PendingNotFoundCount);
            var actual = new InventoryVector[4];
            Assert.AreEqual(OperationStatus.Done, session.DrainNotFound(actual, out count));
            Assert.AreEqual(4, count);
            CollectionAssert.AreEqual(vectors, actual);
            Assert.IsFalse(session.HasPendingNotFound);
            Assert.AreEqual(0, session.PendingNotFoundCount);
            Assert.AreEqual(OperationStatus.Done, session.Consume(Frame("inv"u8, payload), out _));
            Assert.IsTrue(session.HasPendingInventory);
            Assert.IsFalse(session.HasPendingNotFound);
            Assert.AreEqual(OperationStatus.Done, session.DrainNotFound([], out count));
            Assert.AreEqual(0, count);
            Assert.IsTrue(session.HasPendingInventory);
            Assert.AreEqual(OperationStatus.Done, session.DrainInventory(actual, out count));
            Assert.AreEqual(4, count);
            CollectionAssert.AreEqual(vectors, actual);
        }
    }

    [TestMethod]
    public void NotFoundChecksumFaultPartialEofMalformedPayloadAndConfiguredLimitPublishNoEvidence()
    {
        var payload = new byte[73];
        Assert.AreEqual(OperationStatus.Done,
            InventoryPayloadCodec.TryWrite([new(1, default), new(2, default)], payload, 73, out _));
        var frame = Frame("notfound"u8, payload);
        using var corrupt = Ready();
        frame[20] ^= 1;
        Assert.AreEqual(OperationStatus.NeedMoreData, corrupt.Consume(frame.AsSpan(0, frame.Length - 1), out _));
        Assert.IsFalse(corrupt.HasPendingNotFound);
        Assert.AreEqual(OperationStatus.InvalidData, corrupt.Consume(frame.AsSpan(frame.Length - 1), out _));
        Assert.IsFalse(corrupt.HasPendingNotFound);
        Assert.AreEqual(0, corrupt.PendingNotFoundCount);
        Assert.IsFalse(corrupt.HasPendingInventory);

        using var truncated = Ready();
        frame[20] ^= 1;
        Assert.AreEqual(OperationStatus.NeedMoreData, truncated.Consume(frame.AsSpan(0, frame.Length - 1), out _));
        Assert.AreEqual(OperationStatus.InvalidData, truncated.CompleteEndOfInput());
        Assert.IsFalse(truncated.HasPendingNotFound);
        Assert.AreEqual(0, truncated.PendingNotFoundCount);

        using var bounded = Ready(maximumInventoryCount: 1);
        Assert.AreEqual(OperationStatus.InvalidData, bounded.Consume(Frame("notfound"u8, payload), out _));
        Assert.IsFalse(bounded.HasPendingNotFound);
        Assert.AreEqual(0, bounded.PendingNotFoundCount);

        using var malformed = Ready();
        payload[0] = 3;
        Assert.AreEqual(OperationStatus.InvalidData, malformed.Consume(Frame("notfound"u8, payload), out _));
        Assert.IsFalse(malformed.HasPendingNotFound);
        Assert.AreEqual(0, malformed.PendingNotFoundCount);
    }

    [TestMethod]
    public void EmptyAndUnsolicitedNotFoundAreObservedWithoutCreatingRequestOutcomes()
    {
        using var session = Ready();
        Assert.AreEqual(OperationStatus.Done, session.Consume(Frame("notfound"u8, [0]), out _));
        Assert.IsTrue(session.HasPendingNotFound);
        Assert.AreEqual(0, session.PendingNotFoundCount);
        Assert.IsFalse(session.HasPendingInventory);
        Assert.AreEqual(OperationStatus.Done, session.DrainInventory([], out var count));
        Assert.AreEqual(0, count);
        Assert.AreEqual(OperationStatus.DestinationTooSmall, session.Consume(Frame("headers"u8, [0]), out var used));
        Assert.AreEqual(0, used);
        Assert.AreEqual(OperationStatus.Done, session.DrainNotFound([], out count));
        Assert.AreEqual(0, count);
        Assert.IsFalse(session.HasPendingNotFound);

        var payload = new byte[37];
        InventoryVector[] vectors = [new(1, Hash256.DoubleSha256("unsolicited"u8))];
        Assert.AreEqual(OperationStatus.Done, InventoryPayloadCodec.TryWrite(vectors, payload, 37, out _));
        Assert.AreEqual(OperationStatus.Done, session.Consume(Frame("notfound"u8, payload), out _));
        Assert.AreEqual(1, session.PendingNotFoundCount);
        var actual = new InventoryVector[1];
        Assert.AreEqual(OperationStatus.Done, session.DrainNotFound(actual, out count));
        Assert.AreEqual(1, count);
        CollectionAssert.AreEqual(vectors, actual);
        Assert.IsFalse(session.TryGetWrite(out _));
        Assert.AreEqual(OperationStatus.Done, session.CompleteEndOfInput());
    }

    [TestMethod]
    public void HeadersValidateEntireFrameBeforePublishingAndEnforceConfiguredBounds()
    {
        BlockHeader[] headers = [new(1, default, Hash256.DoubleSha256("merkle"u8), 1, 0x1d00ffff, 1)];
        var payload = new byte[82];
        Assert.AreEqual(OperationStatus.Done, HeadersPayloadCodec.TryWrite(headers, payload, out _));
        var frame = Frame("headers"u8, payload);
        using var session = Ready();
        foreach (var value in frame.AsSpan(0, frame.Length - 1))
        {
            Assert.AreEqual(OperationStatus.NeedMoreData, session.Consume([value], out _));
            Assert.IsFalse(session.HasPendingHeaders);
        }

        Assert.AreEqual(OperationStatus.Done, session.Consume(frame.AsSpan(frame.Length - 1), out _));
        Assert.AreEqual(1, session.PendingHeaderCount);
        var actual = new BlockHeader[1];
        Assert.AreEqual(OperationStatus.Done, session.DrainHeaders(actual, out var count));
        Assert.AreEqual(1, count);
        CollectionAssert.AreEqual(headers, actual);
        using var malformed = Ready();
        payload[^1] = 1;
        Assert.AreEqual(OperationStatus.InvalidData, malformed.Consume(Frame("headers"u8, payload), out _));
        Assert.IsFalse(malformed.HasPendingHeaders);
        using var corrupt = Ready();
        frame[20] ^= 1;
        Assert.AreEqual(OperationStatus.InvalidData, corrupt.Consume(frame, out _));
        Assert.IsFalse(corrupt.HasPendingHeaders);

        using var bounded = Ready(maximumInventoryCount: 1);
        var inventoryPayload = new byte[73];
        _ = InventoryPayloadCodec.TryWrite([new(1, default), new(2, default)], inventoryPayload, 73, out _);
        Assert.AreEqual(OperationStatus.InvalidData, bounded.Consume(Frame("inv"u8, inventoryPayload), out _));
        Assert.IsFalse(bounded.HasPendingInventory);
    }

    [TestMethod]
    public void EmptyValidatedControlBatchesStillRequireDrainageAndPartialEofAborts()
    {
        using var session = Ready();
        Assert.AreEqual(OperationStatus.Done, session.Consume(Frame("headers"u8, [0]), out _));
        Assert.IsTrue(session.HasPendingHeaders);
        Assert.AreEqual(0, session.PendingHeaderCount);
        Assert.AreEqual(OperationStatus.DestinationTooSmall, session.Consume(Frame("inv"u8, [0]), out _));
        Assert.AreEqual(OperationStatus.Done, session.DrainHeaders([], out var count));
        Assert.AreEqual(0, count);
        Assert.AreEqual(OperationStatus.Done, session.Consume(Frame("inv"u8, [0]), out _));
        Assert.IsTrue(session.HasPendingInventory);
        Assert.AreEqual(OperationStatus.Done, session.DrainInventory([], out count));
        Assert.AreEqual(0, count);
        Assert.AreEqual(OperationStatus.Done, session.CompleteEndOfInput());

        var sink = new Sink();
        using var truncated = Ready(sink);
        var frame = Frame("tx"u8, Transaction());
        Assert.AreEqual(OperationStatus.NeedMoreData, truncated.Consume(frame.AsSpan(0, frame.Length - 1), out _));
        Assert.AreEqual(OperationStatus.InvalidData, truncated.CompleteEndOfInput());
        Assert.AreEqual(0, sink.Commits);
        Assert.AreEqual(1, sink.Aborts);
    }

    [TestMethod]
    public void TransactionCallbacksStreamAndOnlyCommitValidatedPayloadIdentity()
    {
        var payload = Transaction();
        var sink = new Sink();
        using var session = Ready(sink);
        var frame = Frame("tx"u8, payload);
        for (var index = 0; index < frame.Length; index++)
        {
            Assert.AreEqual(index == frame.Length - 1 ? OperationStatus.Done : OperationStatus.NeedMoreData,
                session.Consume(frame.AsSpan(index, 1), out _));
            Assert.AreEqual(index == frame.Length - 1 ? 1 : 0, sink.Commits);
        }

        Assert.AreEqual(Hash256.DoubleSha256(payload), sink.TransactionId);
        Assert.AreEqual(1, sink.OutputScriptBytes);
        Assert.AreEqual(OperationStatus.Done, session.Consume(frame, out _));
        Assert.AreEqual(2, sink.Commits);
        var corruptSink = new Sink();
        using var corrupt = Ready(corruptSink);
        frame[20] ^= 1;
        Assert.AreEqual(OperationStatus.InvalidData, corrupt.Consume(frame, out _));
        Assert.AreEqual(0, corruptSink.Commits);
        Assert.AreEqual(1, corruptSink.Aborts);
    }

    [TestMethod]
    public void InvalidMoneyAbortsButDoesNotBlockLaterFrames()
    {
        var sink = new Sink();
        using var session = Ready(sink);
        var payload = Transaction();
        BinaryPrimitives.WriteInt64LittleEndian(payload.AsSpan(47), -1);
        Assert.AreEqual(OperationStatus.Done, session.Consume(Frame("tx"u8, payload), out _));
        Assert.AreEqual(1, sink.Aborts);
        Assert.AreEqual(0, sink.Commits);
        Assert.IsFalse(session.TryGetWrite(out _));
        Assert.AreEqual(1, session.PendingMonetaryValidationCount);
        Assert.AreEqual(OperationStatus.DestinationTooSmall, session.Consume(Frame("tx"u8, Transaction()), out _));
        Span<BsvTransactionMonetaryValidation> verdicts = stackalloc BsvTransactionMonetaryValidation[1];
        Assert.AreEqual(OperationStatus.Done, session.DrainMonetaryValidations(verdicts, out var count));
        Assert.AreEqual(1, count);
        Assert.AreEqual(BsvTransactionMonetaryValidationReason.NegativeOutput, verdicts[0].Reason);
        Assert.AreEqual(Hash256.DoubleSha256(payload), verdicts[0].TransactionId);
        Assert.AreEqual(OperationStatus.Done, session.Consume(Frame("tx"u8, Transaction()), out _));
        Assert.AreEqual(1, sink.Commits);
    }

    [TestMethod]
    public void StaleAndForeignWriteLeasesCannotAdvanceAuthority()
    {
        using var session = Ready();
        Assert.AreEqual(OperationStatus.Done, session.RequestTransaction(default));
        Assert.IsTrue(session.TryGetWrite(out var stale));
        Assert.AreEqual(OperationStatus.Done, session.AcknowledgeWrite(stale, 1));
        Assert.AreEqual(OperationStatus.InvalidData, session.AcknowledgeWrite(stale, 1));
        using var first = Ready();
        using var second = Ready();
        Assert.AreEqual(OperationStatus.Done, first.RequestTransaction(default));
        Assert.AreEqual(OperationStatus.Done, second.RequestTransaction(default));
        Assert.IsTrue(first.TryGetWrite(out var foreign));
        Assert.AreEqual(OperationStatus.InvalidData, second.AcknowledgeWrite(foreign, 1));
    }

    [TestMethod]
    public void SwallowedFacadeReentryFromProvisionalSinkCannotCommit()
    {
        var sink = new Sink();
        using var session = Ready(sink);
        sink.OnChunk = () =>
        {
            try
            {
                _ = session.RequestTransaction(default);
            }
            catch (InvalidOperationException)
            {
                // An untrusted callback cannot restore authority by swallowing this failure.
            }
        };
        Assert.ThrowsException<InvalidOperationException>(() => session.Consume(Frame("tx"u8, Transaction()), out _));
        Assert.AreEqual(0, sink.Commits);
    }

    private static BsvPeerObservationSession Ready(Sink? sink = null, int maximumInventoryCount = 3)
    {
        var session = new BsvPeerObservationSession(Magic, 4_000_000, 70001, sink ?? new Sink(), maximumInventoryCount, 2);
        var local = Version(1);
        Assert.AreEqual(OperationStatus.Done, session.StartHandshake(local, 1_048_576));
        _ = DrainWrites(session);
        var versionPayload = new byte[128];
        Assert.AreEqual(OperationStatus.Done, VersionPayloadCodec.TryWrite(versionPayload, Version(2), out var length));
        Assert.AreEqual(OperationStatus.Done, session.Consume(Frame("version"u8, versionPayload.AsSpan(0, length)), out _));
        _ = DrainWrites(session);
        Assert.AreEqual(OperationStatus.Done, session.Consume(Frame("verack"u8, []), out _));
        _ = DrainWrites(session);
        Assert.AreEqual(BsvHandshakeState.Ready, session.HandshakeState);
        return session;
    }

    private static VersionPayload Version(ulong nonce) => new(70016, 0, 1, default, default, nonce, "test"u8, 0, true);

    private static byte[] DrainWrites(BsvPeerObservationSession session)
    {
        using var stream = new MemoryStream();
        while (session.TryGetWrite(out var lease))
        {
            stream.Write(lease.Bytes.Span);
            Assert.AreEqual(OperationStatus.Done, session.AcknowledgeWrite(lease, lease.Bytes.Length));
        }

        return stream.ToArray();
    }

    private static byte[] Frame(ReadOnlySpan<byte> command, ReadOnlySpan<byte> payload)
    {
        var frame = new byte[24 + payload.Length];
        Span<byte> checksum = stackalloc byte[4];
        _ = MessageChecksum.Compute(payload).TryCopyTo(checksum, out _);
        _ = MessageHeader.TryCreateBasic(command, (uint)payload.Length, checksum, out var header);
        _ = MessageHeaderCodec.TryWrite(frame, Magic, header, 4_000_000, out _);
        payload.CopyTo(frame.AsSpan(24));
        return frame;
    }

    private static byte[] Transaction()
    {
        var payload = new byte[61];
        payload[0] = 1;
        payload[4] = 1;
        payload[46] = 1;
        payload[47] = 1;
        payload[55] = 1;
        payload[56] = 0x51;
        return payload;
    }

    private sealed class Sink : ILegacyTransactionSink
    {
        internal int Commits { get; private set; }
        internal int Aborts { get; private set; }
        internal int OutputScriptBytes { get; private set; }
        internal Hash256 TransactionId { get; private set; }
        internal Action? OnChunk { get; set; }
        public void OnTransactionStarted(int version, ulong inputCount) { }
        public void OnInputStarted(ulong inputIndex, in OutPoint previousOutput, ulong scriptLength) { }
        public void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script) { }
        public void OnInputCompleted(ulong inputIndex, uint sequence) { }
        public void OnOutputsStarted(ulong outputCount) { }
        public void OnOutputStarted(ulong outputIndex, long valueSatoshis, ulong scriptLength) { }
        public void OnOutputScriptChunk(ulong outputIndex, ReadOnlySpan<byte> script)
        {
            OutputScriptBytes += script.Length;
            OnChunk?.Invoke();
        }
        public void OnOutputCompleted(ulong outputIndex) { }
        public void OnTransactionCommitted(in LegacyTransactionSummary summary) { Commits++; TransactionId = summary.TransactionId; }
        public void OnTransactionAborted() => Aborts++;
    }
}
