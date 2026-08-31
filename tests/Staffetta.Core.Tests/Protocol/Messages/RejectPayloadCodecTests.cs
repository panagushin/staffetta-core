using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Messages;

namespace Staffetta.Core.Tests.Protocol.Messages;

[TestClass]
public sealed class RejectPayloadCodecTests
{
    [TestMethod]
    public void TransactionRoundTripsRawFieldsAndExposesWireOrderHash()
    {
        var hashBytes = Enumerable.Range(0, Hash256.Length).Select(value => (byte)value).ToArray();
        ReadOnlySpan<byte> reason = [0xff, 0x00, 0xc3, 0x28];
        Span<byte> encoded = stackalloc byte[RejectPayloadCodec.MaximumPayloadLength];

        Assert.AreEqual(
            OperationStatus.Done,
            RejectPayloadCodec.TryWrite(
                encoded,
                "tx"u8,
                0xf1,
                reason,
                hashBytes,
                out var bytesWritten));
        Assert.AreEqual(
            OperationStatus.Done,
            RejectPayloadCodec.TryParse(encoded[..bytesWritten], out var parsed, out var bytesConsumed));

        Assert.AreEqual(bytesWritten, bytesConsumed);
        Assert.IsTrue(parsed.Command.SequenceEqual("tx"u8));
        Assert.AreEqual((byte)0xf1, parsed.Code);
        Assert.IsTrue(parsed.Reason.SequenceEqual(reason));
        Assert.IsTrue(parsed.Data.SequenceEqual(hashBytes));
        Assert.IsTrue(parsed.TryGetObjectHash(out var hash));
        Assert.AreEqual(
            "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
            hash.ToDisplayHex());
    }

    [TestMethod]
    public void VersionAndUnknownCommandsUseDifferentDataRules()
    {
        Span<byte> encoded = stackalloc byte[RejectPayloadCodec.MaximumPayloadLength];
        Assert.AreEqual(
            OperationStatus.Done,
            RejectPayloadCodec.TryWrite(encoded, "version"u8, 0x10, "obsolete"u8, [], out var versionLength));
        Assert.AreEqual(
            OperationStatus.Done,
            RejectPayloadCodec.TryParse(encoded[..versionLength], out var version, out _));
        Assert.IsFalse(version.TryGetObjectHash(out _));

        for (var dataLength = 0; dataLength <= RejectPayloadCodec.MaximumDataLength; dataLength++)
        {
            var data = new byte[dataLength];
            Assert.AreEqual(
                OperationStatus.Done,
                RejectPayloadCodec.TryWrite(encoded, "dsdetected"u8, 0xa5, [], data, out var bytesWritten),
                $"data length {dataLength}");
            Assert.AreEqual(
                OperationStatus.Done,
                RejectPayloadCodec.TryParse(encoded[..bytesWritten], out var parsed, out _),
                $"data length {dataLength}");
            Assert.AreEqual(dataLength, parsed.Data.Length);
            Assert.IsFalse(parsed.TryGetObjectHash(out _));
        }
    }

    [TestMethod]
    public void ReaderAndWriterEnforceCompatibilityBoundaries()
    {
        var command = new byte[RejectPayloadCodec.MaximumCommandLength];
        var reason = new byte[RejectPayloadCodec.MaximumReasonLength];
        var data = new byte[RejectPayloadCodec.MaximumDataLength];
        var maximum = new byte[RejectPayloadCodec.MaximumPayloadLength];

        Assert.AreEqual(
            OperationStatus.Done,
            RejectPayloadCodec.TryWrite(maximum, command, 0x00, reason, data, out var maximumLength));
        Assert.AreEqual(RejectPayloadCodec.MaximumPayloadLength, maximumLength);
        Assert.AreEqual(
            OperationStatus.Done,
            RejectPayloadCodec.TryParse(maximum, out var parsed, out var bytesConsumed));
        Assert.AreEqual(maximum.Length, bytesConsumed);
        Assert.AreEqual(command.Length, parsed.Command.Length);
        Assert.AreEqual(reason.Length, parsed.Reason.Length);
        Assert.AreEqual(data.Length, parsed.Data.Length);

        Assert.AreEqual(
            OperationStatus.InvalidData,
            RejectPayloadCodec.TryWrite(maximum, new byte[command.Length + 1], 0, [], [], out _));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            RejectPayloadCodec.TryWrite(maximum, [], 0, new byte[reason.Length + 1], [], out _));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            RejectPayloadCodec.TryWrite(maximum, [], 0, [], new byte[data.Length + 1], out _));

        var oversizedSource = new byte[RejectPayloadCodec.MaximumPayloadLength + 1];
        Assert.AreEqual(
            OperationStatus.InvalidData,
            RejectPayloadCodec.TryParse(oversizedSource, out _, out var oversizedConsumed));
        Assert.AreEqual(0, oversizedConsumed);
    }

    [TestMethod]
    public void KnownCommandsRequireTheirExactDataShape()
    {
        Span<byte> destination = stackalloc byte[RejectPayloadCodec.MaximumPayloadLength];
        Assert.AreEqual(
            OperationStatus.InvalidData,
            RejectPayloadCodec.TryWrite(destination, "version"u8, 0, [], [0], out _));

        foreach (var command in new[] { "tx"u8.ToArray(), "block"u8.ToArray() })
        {
            Assert.AreEqual(
                OperationStatus.InvalidData,
                RejectPayloadCodec.TryWrite(destination, command, 0, [], new byte[Hash256.Length - 1], out _));
            Assert.AreEqual(
                OperationStatus.InvalidData,
                RejectPayloadCodec.TryWrite(destination, command, 0, [], new byte[Hash256.Length + 1], out _));
            Assert.AreEqual(
                OperationStatus.Done,
                RejectPayloadCodec.TryWrite(destination, command, 0, [], new byte[Hash256.Length], out _));
        }

        byte[] shortTransaction = [2, (byte)'t', (byte)'x', 0x10, 0];
        Assert.AreEqual(
            OperationStatus.NeedMoreData,
            RejectPayloadCodec.TryParse(shortTransaction, out _, out var shortConsumed));
        Assert.AreEqual(0, shortConsumed);

        byte[] versionWithData = [7, (byte)'v', (byte)'e', (byte)'r', (byte)'s', (byte)'i', (byte)'o', (byte)'n', 0x10, 0, 0xaa];
        Assert.AreEqual(
            OperationStatus.InvalidData,
            RejectPayloadCodec.TryParse(versionWithData, out _, out var versionConsumed));
        Assert.AreEqual(0, versionConsumed);
    }

    [TestMethod]
    public void ReaderRejectsNonCanonicalAndOversizedVarBytesWithoutConsumption()
    {
        byte[] nonCanonicalCommand = [0xfd, 2, 0, (byte)'t', (byte)'x', 0x10, 0];
        Assert.AreEqual(
            OperationStatus.InvalidData,
            RejectPayloadCodec.TryParse(nonCanonicalCommand, out _, out var commandConsumed));
        Assert.AreEqual(0, commandConsumed);

        byte[] nonCanonicalReason = [1, (byte)'x', 0x10, 0xfd, 1, 0, (byte)'r'];
        Assert.AreEqual(
            OperationStatus.InvalidData,
            RejectPayloadCodec.TryParse(nonCanonicalReason, out _, out var reasonConsumed));
        Assert.AreEqual(0, reasonConsumed);

        byte[] oversizedCommand = [13];
        Assert.AreEqual(
            OperationStatus.InvalidData,
            RejectPayloadCodec.TryParse(oversizedCommand, out _, out _));

        byte[] oversizedReason = [0, 0x10, 112];
        Assert.AreEqual(
            OperationStatus.InvalidData,
            RejectPayloadCodec.TryParse(oversizedReason, out _, out _));
    }

    [TestMethod]
    public void ReaderReportsEveryTransactionTruncationWithoutConsumption()
    {
        Span<byte> encoded = stackalloc byte[RejectPayloadCodec.MaximumPayloadLength];
        Assert.AreEqual(
            OperationStatus.Done,
            RejectPayloadCodec.TryWrite(encoded, "tx"u8, 0x10, "reason"u8, new byte[Hash256.Length], out var length));

        for (var prefixLength = 0; prefixLength < length; prefixLength++)
        {
            Assert.AreEqual(
                OperationStatus.NeedMoreData,
                RejectPayloadCodec.TryParse(encoded[..prefixLength], out _, out var bytesConsumed),
                $"prefix length {prefixLength}");
            Assert.AreEqual(0, bytesConsumed);
        }
    }

    [TestMethod]
    public void WriterIsAtomicForEveryUndersizedDestinationAndInvalidInput()
    {
        Span<byte> encoded = stackalloc byte[RejectPayloadCodec.MaximumPayloadLength];
        Assert.AreEqual(
            OperationStatus.Done,
            RejectPayloadCodec.TryWrite(encoded, "block"u8, 0x10, "reason"u8, new byte[Hash256.Length], out var requiredLength));

        for (var length = 0; length < requiredLength; length++)
        {
            var destination = new byte[length];
            Array.Fill(destination, (byte)0xa5);
            Assert.AreEqual(
                OperationStatus.DestinationTooSmall,
                RejectPayloadCodec.TryWrite(
                    destination,
                    "block"u8,
                    0x10,
                    "reason"u8,
                    new byte[Hash256.Length],
                    out var bytesWritten),
                $"destination length {length}");
            Assert.AreEqual(0, bytesWritten);
            Assert.IsTrue(destination.AsSpan().IndexOfAnyExcept((byte)0xa5) < 0);
        }

        encoded.Fill(0xa5);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            RejectPayloadCodec.TryWrite(encoded, "version"u8, 0x10, [], [0xaa], out var invalidWritten));
        Assert.AreEqual(0, invalidWritten);
        Assert.IsTrue(encoded.IndexOfAnyExcept((byte)0xa5) < 0);
    }

    [TestMethod]
    public void ParseAndWriteHotPathsDoNotAllocate()
    {
        Span<byte> encoded = stackalloc byte[RejectPayloadCodec.MaximumPayloadLength];
        var hash = new byte[Hash256.Length];
        _ = RejectPayloadCodec.TryWrite(encoded, "tx"u8, 0x10, "reason"u8, hash, out var length);
        _ = RejectPayloadCodec.TryParse(encoded[..length], out _, out _);

        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var iteration = 0; iteration < 1_000; iteration++)
        {
            Assert.AreEqual(
                OperationStatus.Done,
                RejectPayloadCodec.TryWrite(encoded, "tx"u8, 0x10, "reason"u8, hash, out length));
            Assert.AreEqual(
                OperationStatus.Done,
                RejectPayloadCodec.TryParse(encoded[..length], out var parsed, out _));
            Assert.IsTrue(parsed.TryGetObjectHash(out _));
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.AreEqual(0L, allocated);
    }
}
