using System.Buffers;
using System.Buffers.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Encoding;
using Staffetta.Core.Protocol.Messages;

namespace Staffetta.Core.Tests.Protocol.Messages;

[TestClass]
public sealed class InventoryCodecTests
{
    [TestMethod]
    public void VectorCodecPreservesRawTypeAndWireOrderedHash()
    {
        Span<byte> hashBytes = stackalloc byte[Hash256.Length];
        for (var index = 0; index < hashBytes.Length; index++)
        {
            hashBytes[index] = (byte)index;
        }

        Assert.AreEqual(OperationStatus.Done, Hash256.TryCreate(hashBytes, out var hash));
        var vector = new InventoryVector(0x7856_3412, hash);
        Span<byte> encoded = stackalloc byte[InventoryVectorCodec.EncodedLength];

        Assert.AreEqual(
            OperationStatus.Done,
            InventoryVectorCodec.TryWrite(vector, encoded, out var bytesWritten));
        Assert.AreEqual(InventoryVectorCodec.EncodedLength, bytesWritten);
        Assert.AreEqual<uint>(0x7856_3412, BinaryPrimitives.ReadUInt32LittleEndian(encoded));
        Assert.IsTrue(encoded[sizeof(uint)..].SequenceEqual(hashBytes));

        Assert.AreEqual(
            OperationStatus.Done,
            InventoryVectorCodec.TryParse(encoded, out var parsed, out var bytesConsumed));
        Assert.AreEqual(encoded.Length, bytesConsumed);
        Assert.AreEqual(vector, parsed);
        Assert.AreEqual(OperationStatus.NeedMoreData, InventoryVectorCodec.TryParse(encoded[..^1], out _, out _));

        Span<byte> shortDestination = stackalloc byte[InventoryVectorCodec.EncodedLength - 1];
        shortDestination.Fill(0xa5);
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            InventoryVectorCodec.TryWrite(vector, shortDestination, out var shortBytesWritten));
        Assert.AreEqual(0, shortBytesWritten);
        Assert.IsTrue(shortDestination.IndexOfAnyExcept((byte)0xa5) < 0);
    }

    [TestMethod]
    public void PayloadWriterIsCanonicalBoundedAndAtomicOnFailure()
    {
        Span<byte> empty = stackalloc byte[1];
        Assert.AreEqual(
            OperationStatus.Done,
            InventoryPayloadCodec.TryWrite([], empty, 1, out var emptyLength));
        Assert.AreEqual(1, emptyLength);
        Assert.AreEqual((byte)0, empty[0]);

        var vectors = new[] { CreateVector(1, 0x11), CreateVector(uint.MaxValue, 0x22) };
        Span<byte> encoded = stackalloc byte[1 + (2 * InventoryVectorCodec.EncodedLength)];
        Assert.AreEqual(
            OperationStatus.Done,
            InventoryPayloadCodec.TryWrite(vectors, encoded, (ulong)encoded.Length, out var bytesWritten));
        Assert.AreEqual(encoded.Length, bytesWritten);
        Assert.AreEqual((byte)2, encoded[0]);

        Span<byte> tooSmall = stackalloc byte[encoded.Length - 1];
        tooSmall.Fill(0xa5);
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            InventoryPayloadCodec.TryWrite(vectors, tooSmall, (ulong)encoded.Length, out var shortLength));
        Assert.AreEqual(0, shortLength);
        Assert.IsTrue(tooSmall.IndexOfAnyExcept((byte)0xa5) < 0);

        encoded.Fill(0xa5);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            InventoryPayloadCodec.TryWrite(vectors, encoded, (ulong)encoded.Length - 1, out var boundedLength));
        Assert.AreEqual(0, boundedLength);
        Assert.IsTrue(encoded.IndexOfAnyExcept((byte)0xa5) < 0);
    }

    [TestMethod]
    public void IncrementalParserHandlesEmptyAndEverySingleVectorSplit()
    {
        var vector = CreateVector(0xfeed_beef, 0x42);
        var payload = new byte[1 + InventoryVectorCodec.EncodedLength];
        Assert.AreEqual(
            OperationStatus.Done,
            InventoryPayloadCodec.TryWrite([vector], payload, (ulong)payload.Length, out _));

        var parser = new IncrementalInventoryPayloadParser();
        parser.Reset(1);
        Assert.AreEqual(OperationStatus.Done, parser.Consume([0], [], out var emptyConsumed, out var emptyWritten));
        Assert.AreEqual(1, emptyConsumed);
        Assert.AreEqual(0, emptyWritten);
        Assert.AreEqual<ulong>(0, parser.VectorCount);
        Assert.AreEqual(OperationStatus.Done, parser.Complete());

        var parsed = new InventoryVector[1];
        for (var split = 0; split <= payload.Length; split++)
        {
            parser.Reset((ulong)payload.Length);
            var firstStatus = parser.Consume(payload.AsSpan(0, split), parsed, out var firstConsumed, out var firstWritten);
            Assert.AreEqual(split, firstConsumed, $"split {split} first consumed");
            if (split < payload.Length)
            {
                Assert.AreEqual(OperationStatus.NeedMoreData, firstStatus, $"split {split} first status");
            }

            var secondStatus = parser.Consume(
                payload.AsSpan(split),
                parsed.AsSpan(firstWritten),
                out var secondConsumed,
                out var secondWritten);
            Assert.AreEqual(OperationStatus.Done, secondStatus, $"split {split} second status");
            Assert.AreEqual(payload.Length - split, secondConsumed, $"split {split} second consumed");
            Assert.AreEqual(1, firstWritten + secondWritten, $"split {split} vectors");
            Assert.AreEqual(vector, parsed[0], $"split {split} vector");
            Assert.AreEqual(OperationStatus.Done, parser.Complete());
        }
    }

    [TestMethod]
    public void CountPrefixesSplitCanonicallyAtAllEncodingTransitions()
    {
        ulong[] counts = [0, 1, 252, 253, 65_535, 65_536];
        var parser = new IncrementalInventoryPayloadParser();
        Span<byte> prefix = stackalloc byte[9];
        foreach (var count in counts)
        {
            Assert.AreEqual(OperationStatus.Done, CompactSize.Write(count, prefix, out var prefixLength));
            var declaredLength = (ulong)prefixLength + (count * InventoryVectorCodec.EncodedLength);

            for (var split = 0; split <= prefixLength; split++)
            {
                parser.Reset(declaredLength);
                var firstStatus = parser.Consume(prefix[..split], [], out var firstConsumed, out _);
                Assert.AreEqual(split, firstConsumed, $"count {count}, split {split}");
                if (split < prefixLength)
                {
                    Assert.AreEqual(OperationStatus.NeedMoreData, firstStatus);
                }

                var secondStatus = parser.Consume(prefix[split..prefixLength], [], out var secondConsumed, out _);
                Assert.AreEqual(prefixLength - split, secondConsumed);
                Assert.AreEqual(
                    count == 0 ? OperationStatus.Done : OperationStatus.DestinationTooSmall,
                    secondStatus,
                    $"count {count}, split {split}");
                Assert.AreEqual(count, parser.VectorCount);
            }
        }
    }

    [TestMethod]
    public void ParserRejectsNonCanonicalMismatchAndOverflowBeforeVectors()
    {
        byte[][] nonCanonical =
        [
            [0xfd, 0xfc, 0x00],
            [0xfe, 0xff, 0xff, 0x00, 0x00],
            [0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
        ];

        var parser = new IncrementalInventoryPayloadParser();
        foreach (var prefix in nonCanonical)
        {
            parser.Reset((ulong)prefix.Length);
            Assert.AreEqual(OperationStatus.InvalidData, parser.Consume(prefix, [], out var consumed, out var written));
            Assert.AreEqual(prefix.Length, consumed);
            Assert.AreEqual(0, written);
            Assert.AreEqual(OperationStatus.InvalidData, parser.Consume([], [], out _, out _));
        }

        parser.Reset(1 + InventoryVectorCodec.EncodedLength);
        Assert.AreEqual(OperationStatus.InvalidData, parser.Consume([2], [], out var mismatchConsumed, out _));
        Assert.AreEqual(1, mismatchConsumed);

        byte[] overflow = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        parser.Reset(ulong.MaxValue);
        Assert.AreEqual(OperationStatus.InvalidData, parser.Consume(overflow, [], out var overflowConsumed, out _));
        Assert.AreEqual(overflow.Length, overflowConsumed);
    }

    [TestMethod]
    public void DestinationBackpressureNeverConsumesNextVector()
    {
        var first = CreateVector(1, 0x11);
        var second = CreateVector(2, 0x22);
        var payload = new byte[1 + (2 * InventoryVectorCodec.EncodedLength)];
        Assert.AreEqual(
            OperationStatus.Done,
            InventoryPayloadCodec.TryWrite([first, second], payload, (ulong)payload.Length, out _));

        var parser = new IncrementalInventoryPayloadParser();
        parser.Reset((ulong)payload.Length);
        Span<InventoryVector> destination = stackalloc InventoryVector[1];
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            parser.Consume(payload, destination, out var consumed, out var written));
        Assert.AreEqual(1 + InventoryVectorCodec.EncodedLength, consumed);
        Assert.AreEqual(1, written);
        Assert.AreEqual(first, destination[0]);

        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            parser.Consume(payload.AsSpan(consumed), [], out var blockedConsumed, out var blockedWritten));
        Assert.AreEqual(0, blockedConsumed);
        Assert.AreEqual(0, blockedWritten);

        Assert.AreEqual(
            OperationStatus.Done,
            parser.Consume(payload.AsSpan(consumed), destination, out var finalConsumed, out var finalWritten));
        Assert.AreEqual(InventoryVectorCodec.EncodedLength, finalConsumed);
        Assert.AreEqual(1, finalWritten);
        Assert.AreEqual(second, destination[0]);

        parser.Reset((ulong)payload.Length);
        Assert.AreEqual(
            OperationStatus.NeedMoreData,
            parser.Consume(payload.AsSpan(0, 11), destination, out var partialConsumed, out _));
        Assert.AreEqual(11, partialConsumed);
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            parser.Consume(payload.AsSpan(11), [], out blockedConsumed, out _));
        Assert.AreEqual(0, blockedConsumed);
    }

    [TestMethod]
    public void ParserLeavesTrailingBytesAndCompletionFaultsTruncationUntilReset()
    {
        var vector = CreateVector(1, 0x33);
        var payload = new byte[1 + InventoryVectorCodec.EncodedLength + 2];
        Assert.AreEqual(
            OperationStatus.Done,
            InventoryPayloadCodec.TryWrite([vector], payload, (ulong)payload.Length - 2, out var payloadLength));
        payload[^2] = 0xaa;
        payload[^1] = 0xbb;

        var parser = new IncrementalInventoryPayloadParser();
        parser.Reset((ulong)payloadLength);
        Span<InventoryVector> destination = stackalloc InventoryVector[1];
        Assert.AreEqual(OperationStatus.Done, parser.Consume(payload, destination, out var consumed, out var written));
        Assert.AreEqual(payloadLength, consumed);
        Assert.AreEqual(1, written);

        parser.Reset((ulong)payloadLength);
        Assert.AreEqual(OperationStatus.NeedMoreData, parser.Consume(payload.AsSpan(0, 12), destination, out _, out _));
        Assert.AreEqual(OperationStatus.InvalidData, parser.Complete());
        Assert.AreEqual(OperationStatus.InvalidData, parser.Consume([], destination, out _, out _));

        parser.Reset(1);
        Assert.AreEqual(OperationStatus.Done, parser.Consume([0], [], out _, out _));
    }

    [TestMethod]
    public void ParserStreamsTwentyNineThousandVectorsWithZeroWarmAllocationSlope()
    {
        const int vectorCount = 29_127;
        Span<byte> prefix = stackalloc byte[9];
        Assert.AreEqual(OperationStatus.Done, CompactSize.Write(vectorCount, prefix, out var prefixLength));
        var declaredLength = (ulong)prefixLength + ((ulong)vectorCount * InventoryVectorCodec.EncodedLength);

        var vector = CreateVector(1, 0x5a);
        var batch = new byte[8 * InventoryVectorCodec.EncodedLength];
        for (var offset = 0; offset < batch.Length; offset += InventoryVectorCodec.EncodedLength)
        {
            Assert.AreEqual(
                OperationStatus.Done,
                InventoryVectorCodec.TryWrite(vector, batch.AsSpan(offset), out _));
        }

        var destination = new InventoryVector[8];
        var parser = new IncrementalInventoryPayloadParser();
        Assert.IsTrue(RunLargeParse(parser, prefix[..prefixLength], batch, destination, vectorCount, declaredLength));

        var before = GC.GetAllocatedBytesForCurrentThread();
        var succeeded = RunLargeParse(parser, prefix[..prefixLength], batch, destination, vectorCount, declaredLength);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.IsTrue(succeeded);
        Assert.AreEqual(0L, allocated);
        Assert.AreEqual<ulong>(vectorCount, parser.VectorsRead);
    }

    private static bool RunLargeParse(
        IncrementalInventoryPayloadParser parser,
        ReadOnlySpan<byte> prefix,
        byte[] batch,
        InventoryVector[] destination,
        int vectorCount,
        ulong declaredLength)
    {
        parser.Reset(declaredLength);
        var status = parser.Consume(prefix, destination, out var prefixConsumed, out var prefixWritten);
        if (status != OperationStatus.NeedMoreData ||
            prefixConsumed != prefix.Length ||
            prefixWritten != 0)
        {
            return false;
        }

        var remaining = vectorCount;
        while (remaining > 0)
        {
            var currentCount = Math.Min(destination.Length, remaining);
            var source = batch.AsSpan(0, currentCount * InventoryVectorCodec.EncodedLength);
            status = parser.Consume(source, destination, out var consumed, out var written);
            if (consumed != source.Length || written != currentCount)
            {
                return false;
            }

            remaining -= currentCount;
            var expected = remaining == 0
                ? OperationStatus.Done
                : OperationStatus.DestinationTooSmall;
            if (status != expected)
            {
                return false;
            }
        }

        return parser.Complete() == OperationStatus.Done;
    }

    private static InventoryVector CreateVector(uint type, byte hashByte)
    {
        Span<byte> hashBytes = stackalloc byte[Hash256.Length];
        hashBytes.Fill(hashByte);
        Assert.AreEqual(OperationStatus.Done, Hash256.TryCreate(hashBytes, out var hash));
        return new InventoryVector(type, hash);
    }
}
