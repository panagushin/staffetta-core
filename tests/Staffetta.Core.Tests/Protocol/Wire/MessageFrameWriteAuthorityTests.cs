using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Tests.Protocol.Wire;

[TestClass]
public sealed class MessageFrameWriteAuthorityTests
{
    private const ulong MaximumPayloadLength = ulong.MaxValue;

    private static readonly byte[] NetworkMagic = [0xe3, 0xe1, 0xf3, 0xe8];

    [TestMethod]
    public void BasicFrameMatchesCodecAcrossPayloadChunksAndOneByteWrites()
    {
        var payload = new byte[257];
        for (var index = 0; index < payload.Length; index++)
        {
            payload[index] = (byte)index;
        }

        var header = CreateBasicHeader("tx"u8, payload);
        var expectedHeader = EncodeHeader(header);
        var expectedFrame = new byte[expectedHeader.Length + payload.Length];
        expectedHeader.CopyTo(expectedFrame, 0);
        payload.CopyTo(expectedFrame, expectedHeader.Length);
        var writtenFrame = new byte[expectedFrame.Length];
        using var authority = new MessageFrameWriteAuthority();

        Assert.AreEqual(
            OperationStatus.Done,
            authority.Start(NetworkMagic, header, MaximumPayloadLength));
        WriteFrame(
            authority,
            payload,
            writtenFrame,
            payloadChunkLength: 17,
            maximumWriteLength: 1);

        Assert.IsTrue(authority.IsComplete);
        Assert.AreEqual((ulong)payload.Length, authority.PayloadBytesAcknowledged);
        CollectionAssert.AreEqual(expectedFrame, writtenFrame);
    }

    [TestMethod]
    public void ExtendedHeaderMatchesCodecAcrossShortAcknowledgements()
    {
        const ulong payloadLength = (ulong)uint.MaxValue + 123;
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateExtended("tx"u8, payloadLength, out var header));
        var expectedHeader = EncodeHeader(header);
        var writtenHeader = new byte[expectedHeader.Length];
        using var authority = new MessageFrameWriteAuthority();
        Assert.AreEqual(
            OperationStatus.Done,
            authority.Start(NetworkMagic, header, MaximumPayloadLength));

        WritePendingHeader(authority, writtenHeader, maximumWriteLength: 3);

        Assert.AreEqual(MessageFrameWritePhase.AwaitingPayload, authority.Phase);
        Assert.AreEqual(payloadLength, authority.PayloadBytesRemaining);
        Assert.IsFalse(authority.IsComplete);
        CollectionAssert.AreEqual(expectedHeader, writtenHeader);
        Assert.AreEqual(OperationStatus.Done, authority.Abort());
    }

    [TestMethod]
    public void ZeroPayloadCompletesOnlyWithTheLastHeaderByte()
    {
        var header = CreateBasicHeader("verack"u8, []);
        using var authority = new MessageFrameWriteAuthority();
        Assert.AreEqual(
            OperationStatus.Done,
            authority.Start(NetworkMagic, header, MaximumPayloadLength));
        var headerLength = authority.PendingSegment.Length;

        Assert.AreEqual(
            OperationStatus.Done,
            authority.Acknowledge(authority.PendingSegment, headerLength - 1));
        Assert.AreEqual(MessageFrameWritePhase.Header, authority.Phase);
        Assert.IsFalse(authority.IsComplete);
        Assert.AreEqual(1, authority.PendingSegment.Length);

        Assert.AreEqual(OperationStatus.Done, authority.Acknowledge(authority.PendingSegment, 1));
        Assert.IsTrue(authority.IsComplete);
        Assert.IsTrue(authority.PendingSegment.IsEmpty);
    }

    [TestMethod]
    public void PayloadChunkIsBorrowedStableAndCannotBeReplacedBeforeAcknowledgement()
    {
        byte[] payload = [1, 2, 3, 4];
        var header = CreateBasicHeader("tx"u8, payload);
        using var authority = new MessageFrameWriteAuthority();
        Assert.AreEqual(
            OperationStatus.Done,
            authority.Start(NetworkMagic, header, MaximumPayloadLength));
        Assert.AreEqual(
            OperationStatus.Done,
            authority.Acknowledge(authority.PendingSegment, authority.PendingSegment.Length));
        Assert.AreEqual(OperationStatus.Done, authority.ProvidePayloadChunk(payload));

        Assert.IsTrue(authority.PendingSegment.Memory.Equals(payload.AsMemory()));
        Assert.AreEqual(OperationStatus.Done, authority.Acknowledge(authority.PendingSegment, 1));
        Assert.AreEqual(3, authority.PendingSegment.Length);
        Assert.IsTrue(authority.PendingSegment.Memory.Equals(payload.AsMemory(1)));

        Assert.AreEqual(
            OperationStatus.InvalidData,
            authority.ProvidePayloadChunk(new byte[] { 5 }));
        Assert.IsTrue(authority.IsFaulted);
        Assert.IsTrue(authority.PendingSegment.IsEmpty);
    }

    [TestMethod]
    public void MoreThanFourGiBUsesFixedMemoryAndZeroWarmChunkAckAllocation()
    {
        const ulong payloadLength = (ulong)uint.MaxValue + 123;
        var chunk = new byte[1024 * 1024];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateExtended("tx"u8, payloadLength, out var header));
        using var authority = new MessageFrameWriteAuthority();
        Assert.AreEqual(
            OperationStatus.Done,
            authority.Start(NetworkMagic, header, MaximumPayloadLength));
        Assert.AreEqual(
            OperationStatus.Done,
            authority.Acknowledge(authority.PendingSegment, authority.PendingSegment.Length));

        Assert.AreEqual(OperationStatus.Done, authority.ProvidePayloadChunk(chunk));
        Assert.AreEqual(
            OperationStatus.Done,
            authority.Acknowledge(authority.PendingSegment, chunk.Length));
        var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        var statusesAreValid = true;
        while (authority.PayloadBytesRemaining != 0)
        {
            var length = (int)Math.Min((ulong)chunk.Length, authority.PayloadBytesRemaining);
            statusesAreValid &=
                authority.ProvidePayloadChunk(chunk.AsMemory(0, length)) == OperationStatus.Done;
            statusesAreValid &=
                authority.Acknowledge(authority.PendingSegment, length) == OperationStatus.Done;
        }

        var allocatedAfter = GC.GetAllocatedBytesForCurrentThread();

        Assert.IsTrue(statusesAreValid);
        Assert.AreEqual(allocatedBefore, allocatedAfter);
        Assert.IsTrue(authority.IsComplete);
        Assert.AreEqual(payloadLength, authority.PayloadBytesAcknowledged);
        Assert.IsTrue(authority.PendingSegment.IsEmpty);
    }

    [TestMethod]
    public void AcknowledgementMisuseFaultsStickyWithoutPublishingComplete()
    {
        var header = CreateBasicHeader("tx"u8, [1, 2, 3]);
        using var zero = StartAuthority(header);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            zero.Acknowledge(zero.PendingSegment, 0));
        AssertStickyFault(zero, header);

        using var headerOverAck = StartAuthority(header);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            headerOverAck.Acknowledge(
                headerOverAck.PendingSegment,
                headerOverAck.PendingSegment.Length + 1));
        AssertStickyFault(headerOverAck, header);

        using var payloadBeforeHeader = StartAuthority(header);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            payloadBeforeHeader.ProvidePayloadChunk(new byte[] { 1 }));
        AssertStickyFault(payloadBeforeHeader, header);

        using var payloadOverAck = StartAuthority(header);
        Assert.AreEqual(
            OperationStatus.Done,
            payloadOverAck.Acknowledge(
                payloadOverAck.PendingSegment,
                payloadOverAck.PendingSegment.Length));
        Assert.AreEqual(
            OperationStatus.Done,
            payloadOverAck.ProvidePayloadChunk(new byte[] { 1, 2, 3 }));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            payloadOverAck.Acknowledge(payloadOverAck.PendingSegment, 4));
        AssertStickyFault(payloadOverAck, header);
    }

    [TestMethod]
    public void HeaderLeaseIsStaleAfterAbortResetAndRestart()
    {
        var header = CreateBasicHeader("tx"u8, [1]);
        using var authority = StartAuthority(header);
        var staleHeader = authority.PendingSegment;
        Assert.AreEqual(OperationStatus.Done, authority.Abort());
        Assert.AreEqual(OperationStatus.Done, authority.Reset());
        Assert.AreEqual(
            OperationStatus.Done,
            authority.Start(NetworkMagic, header, MaximumPayloadLength));

        Assert.AreEqual(OperationStatus.InvalidData, authority.Acknowledge(staleHeader, 1));
        Assert.IsTrue(authority.IsFaulted);
        Assert.IsFalse(authority.IsComplete);
    }

    [TestMethod]
    public void PayloadLeaseIsStaleAfterTheNextChunkIsProvided()
    {
        byte[] payload = [1, 2];
        var header = CreateBasicHeader("tx"u8, payload);
        using var authority = StartAuthority(header);
        Assert.AreEqual(
            OperationStatus.Done,
            authority.Acknowledge(authority.PendingSegment, authority.PendingSegment.Length));
        Assert.AreEqual(OperationStatus.Done, authority.ProvidePayloadChunk(payload.AsMemory(0, 1)));
        var firstChunk = authority.PendingSegment;
        Assert.AreEqual(OperationStatus.Done, authority.Acknowledge(firstChunk, 1));
        Assert.AreEqual(OperationStatus.Done, authority.ProvidePayloadChunk(payload.AsMemory(1, 1)));

        Assert.AreEqual(OperationStatus.InvalidData, authority.Acknowledge(firstChunk, 1));
        Assert.IsTrue(authority.IsFaulted);
        Assert.IsFalse(authority.IsComplete);
    }

    [TestMethod]
    public void PartialAcknowledgementCannotBeDuplicatedWithTheOldLease()
    {
        var header = CreateBasicHeader("tx"u8, [1]);
        using var authority = StartAuthority(header);
        var originalHeader = authority.PendingSegment;
        Assert.AreEqual(OperationStatus.Done, authority.Acknowledge(originalHeader, 1));

        Assert.AreEqual(OperationStatus.InvalidData, authority.Acknowledge(originalHeader, 1));
        Assert.IsTrue(authority.IsFaulted);
        Assert.IsFalse(authority.IsComplete);
    }

    [TestMethod]
    public void LeaseFromAnotherAuthorityCannotAcknowledgeTheSamePayloadMemory()
    {
        byte[] payload = [1, 2, 3];
        var header = CreateBasicHeader("tx"u8, payload);
        using var first = StartAuthority(header);
        using var second = StartAuthority(header);
        Assert.AreEqual(
            OperationStatus.Done,
            first.Acknowledge(first.PendingSegment, first.PendingSegment.Length));
        Assert.AreEqual(
            OperationStatus.Done,
            second.Acknowledge(second.PendingSegment, second.PendingSegment.Length));
        Assert.AreEqual(OperationStatus.Done, first.ProvidePayloadChunk(payload));
        Assert.AreEqual(OperationStatus.Done, second.ProvidePayloadChunk(payload));

        Assert.AreEqual(
            OperationStatus.InvalidData,
            second.Acknowledge(first.PendingSegment, 1));
        Assert.IsTrue(second.IsFaulted);
        Assert.IsFalse(second.IsComplete);
        Assert.IsFalse(first.IsFaulted);
    }

    [TestMethod]
    public void CompleteAndAbortRequireExplicitResetBeforeReuse()
    {
        var firstHeader = CreateBasicHeader("verack"u8, []);
        var secondHeader = CreateBasicHeader("ping"u8, new byte[8]);
        using var completed = StartAuthority(firstHeader);
        Assert.AreEqual(
            OperationStatus.Done,
            completed.Acknowledge(completed.PendingSegment, completed.PendingSegment.Length));
        Assert.IsTrue(completed.IsComplete);
        Assert.AreEqual(OperationStatus.Done, completed.Reset());
        Assert.AreEqual(
            OperationStatus.Done,
            completed.Start(NetworkMagic, secondHeader, MaximumPayloadLength));
        Assert.AreEqual(MessageFrameWritePhase.Header, completed.Phase);

        using var aborted = StartAuthority(secondHeader);
        Assert.AreEqual(OperationStatus.Done, aborted.Abort());
        Assert.AreEqual(MessageFrameWritePhase.Aborted, aborted.Phase);
        Assert.IsTrue(aborted.PendingSegment.IsEmpty);
        Assert.AreEqual(OperationStatus.Done, aborted.Reset());
        Assert.AreEqual(
            OperationStatus.Done,
            aborted.Start(NetworkMagic, firstHeader, MaximumPayloadLength));

        using var withoutReset = StartAuthority(firstHeader);
        Assert.AreEqual(
            OperationStatus.Done,
            withoutReset.Acknowledge(
                withoutReset.PendingSegment,
                withoutReset.PendingSegment.Length));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            withoutReset.Start(NetworkMagic, firstHeader, MaximumPayloadLength));
        Assert.IsTrue(withoutReset.IsFaulted);
    }

    [TestMethod]
    public void DisposeReleasesThePendingSegmentAndIsIdempotent()
    {
        var payload = new byte[8];
        var header = CreateBasicHeader("ping"u8, payload);
        var authority = StartAuthority(header);
        Assert.AreEqual(
            OperationStatus.Done,
            authority.Acknowledge(authority.PendingSegment, authority.PendingSegment.Length));
        Assert.AreEqual(OperationStatus.Done, authority.ProvidePayloadChunk(payload));

        authority.Dispose();
        authority.Dispose();

        Assert.AreEqual(MessageFrameWritePhase.Disposed, authority.Phase);
        Assert.IsTrue(authority.PendingSegment.IsEmpty);
        Assert.AreEqual(0UL, authority.PayloadBytesRemaining);
        Assert.ThrowsException<ObjectDisposedException>(
            () => authority.Acknowledge(default, 1));
        Assert.ThrowsException<ObjectDisposedException>(
            () => authority.ProvidePayloadChunk(payload));
    }

    [TestMethod]
    public void WarmPartialAcknowledgementsAllocateNothing()
    {
        var payload = new byte[1024];
        var header = CreateBasicHeader("tx"u8, payload);
        using var authority = StartAuthority(header);
        Assert.AreEqual(
            OperationStatus.Done,
            authority.Acknowledge(authority.PendingSegment, authority.PendingSegment.Length));
        Assert.AreEqual(OperationStatus.Done, authority.ProvidePayloadChunk(payload));
        Assert.AreEqual(OperationStatus.Done, authority.Acknowledge(authority.PendingSegment, 1));

        var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        var statusesAreValid = true;
        for (var index = 1; index < payload.Length; index++)
        {
            statusesAreValid &=
                authority.Acknowledge(authority.PendingSegment, 1) == OperationStatus.Done;
        }

        var allocatedAfter = GC.GetAllocatedBytesForCurrentThread();
        Assert.IsTrue(statusesAreValid);
        Assert.AreEqual(allocatedBefore, allocatedAfter);
        Assert.IsTrue(authority.IsComplete);
    }

    private static MessageFrameWriteAuthority StartAuthority(in MessageHeader header)
    {
        var authority = new MessageFrameWriteAuthority();
        Assert.AreEqual(
            OperationStatus.Done,
            authority.Start(NetworkMagic, header, MaximumPayloadLength));
        return authority;
    }

    private static void AssertStickyFault(
        MessageFrameWriteAuthority authority,
        in MessageHeader header)
    {
        Assert.IsTrue(authority.IsFaulted);
        Assert.IsFalse(authority.IsComplete);
        Assert.IsTrue(authority.PendingSegment.IsEmpty);
        Assert.AreEqual(OperationStatus.InvalidData, authority.Acknowledge(default, 1));
        Assert.AreEqual(OperationStatus.InvalidData, authority.Reset());
        Assert.AreEqual(
            OperationStatus.InvalidData,
            authority.Start(NetworkMagic, header, MaximumPayloadLength));
    }

    private static void WriteFrame(
        MessageFrameWriteAuthority authority,
        ReadOnlyMemory<byte> payload,
        Span<byte> destination,
        int payloadChunkLength,
        int maximumWriteLength)
    {
        var destinationOffset = 0;
        var payloadOffset = 0;
        while (!authority.IsComplete)
        {
            if (authority.Phase == MessageFrameWritePhase.AwaitingPayload)
            {
                var length = Math.Min(payloadChunkLength, payload.Length - payloadOffset);
                Assert.IsTrue(length > 0);
                Assert.AreEqual(
                    OperationStatus.Done,
                    authority.ProvidePayloadChunk(payload.Slice(payloadOffset, length)));
                payloadOffset += length;
            }

            var pending = authority.PendingSegment;
            Assert.IsFalse(pending.IsEmpty);
            var writeLength = Math.Min(maximumWriteLength, pending.Length);
            pending.Span[..writeLength].CopyTo(destination[destinationOffset..]);
            Assert.AreEqual(OperationStatus.Done, authority.Acknowledge(pending, writeLength));
            destinationOffset += writeLength;
        }

        Assert.AreEqual(destination.Length, destinationOffset);
        Assert.AreEqual(payload.Length, payloadOffset);
    }

    private static void WritePendingHeader(
        MessageFrameWriteAuthority authority,
        Span<byte> destination,
        int maximumWriteLength)
    {
        var offset = 0;
        while (authority.Phase == MessageFrameWritePhase.Header)
        {
            var pending = authority.PendingSegment;
            var length = Math.Min(maximumWriteLength, pending.Length);
            pending.Span[..length].CopyTo(destination[offset..]);
            Assert.AreEqual(OperationStatus.Done, authority.Acknowledge(pending, length));
            offset += length;
        }

        Assert.AreEqual(destination.Length, offset);
    }

    private static MessageHeader CreateBasicHeader(
        ReadOnlySpan<byte> command,
        ReadOnlySpan<byte> payload)
    {
        var checksum = MessageChecksum.Compute(payload);
        Span<byte> checksumBytes = stackalloc byte[MessageChecksum.Length];
        checksum.WriteTo(checksumBytes);
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic(
                command,
                checked((uint)payload.Length),
                checksumBytes,
                out var header));
        return header;
    }

    private static byte[] EncodeHeader(in MessageHeader header)
    {
        var encoded = new byte[header.EncodedLength];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(
                encoded,
                NetworkMagic,
                header,
                MaximumPayloadLength,
                out var written));
        Assert.AreEqual(encoded.Length, written);
        return encoded;
    }
}
