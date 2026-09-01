using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Discovery;
using Staffetta.Core.Protocol.Handshake;

namespace Staffetta.Core.Tests.Protocol.Discovery;

[TestClass]
public sealed class LegacyAddressPayloadCodecTests
{
    [TestMethod]
    public void ZeroCountUsesCanonicalOneBytePayloadAndNoRecordDestination()
    {
        Span<byte> payload = stackalloc byte[1];
        Assert.AreEqual(
            OperationStatus.Done,
            LegacyAddressPayloadCodec.TryWrite([], payload, out var bytesWritten));
        Assert.AreEqual(1, bytesWritten);
        Assert.AreEqual((byte)0, payload[0]);

        Assert.AreEqual(
            OperationStatus.Done,
            LegacyAddressPayloadCodec.TryParse(payload, [], out var recordsWritten, out var bytesConsumed));
        Assert.AreEqual(0, recordsWritten);
        Assert.AreEqual(1, bytesConsumed);
    }

    [TestMethod]
    public void RoundTripPreservesTimestampServicesAddressesAndAdvertisedPorts()
    {
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(
            0xfedc_ba98_7654_3210,
            [192, 0, 2, 7],
            18_333,
            out var ipv4));
        var ipv6 = new NetworkAddress(
            3,
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
            9_999);
        LegacyAddressRecord[] expected =
        [
            new(1_800_000_001, ipv4),
            new(uint.MaxValue, ipv6),
        ];
        var encoded = new byte[1 + (expected.Length * LegacyAddressPayloadCodec.RecordLength)];

        Assert.AreEqual(
            OperationStatus.Done,
            LegacyAddressPayloadCodec.TryWrite(expected, encoded, out var bytesWritten));
        Assert.AreEqual(encoded.Length, bytesWritten);
        Assert.AreEqual((byte)expected.Length, encoded[0]);

        Span<LegacyAddressRecord> actual = stackalloc LegacyAddressRecord[expected.Length];
        Assert.AreEqual(
            OperationStatus.Done,
            LegacyAddressPayloadCodec.TryParse(encoded, actual, out var recordsWritten, out var bytesConsumed));
        Assert.AreEqual(expected.Length, recordsWritten);
        Assert.AreEqual(encoded.Length, bytesConsumed);
        Assert.IsTrue(actual.SequenceEqual(expected));
        Assert.AreEqual<ushort>(18_333, actual[0].Address.Port);
        Assert.AreEqual<ushort>(9_999, actual[1].Address.Port);
        Assert.IsTrue(actual[0].Address.IsIpv4Mapped);
        Assert.IsFalse(actual[1].Address.IsIpv4Mapped);
    }

    [TestMethod]
    public void ParseRequiresCanonicalCountAndExactWholePayload()
    {
        AssertParseFailure([0xfd, 0x01, 0x00], OperationStatus.InvalidData);
        AssertParseFailure([0xfd, 0xe9, 0x03], OperationStatus.InvalidData);

        var record = CreateIpv4Record(42, [203, 0, 113, 4], 8_333);
        var canonical = new byte[1 + LegacyAddressPayloadCodec.RecordLength];
        Assert.AreEqual(
            OperationStatus.Done,
            LegacyAddressPayloadCodec.TryWrite([record], canonical, out _));

        for (var length = 0; length < canonical.Length; length++)
        {
            AssertParseFailure(canonical.AsSpan(0, length), OperationStatus.NeedMoreData);
        }

        var trailing = new byte[canonical.Length + 1];
        canonical.CopyTo(trailing, 0);
        trailing[^1] = 0xa5;
        AssertParseFailure(trailing, OperationStatus.InvalidData);
    }

    [TestMethod]
    public void DestinationAndCountBoundsFailWithoutPartialOutput()
    {
        var first = CreateIpv4Record(1, [192, 0, 2, 1], 1);
        var second = CreateIpv4Record(2, [192, 0, 2, 2], 2);
        var encoded = new byte[1 + (2 * LegacyAddressPayloadCodec.RecordLength)];
        Assert.AreEqual(
            OperationStatus.Done,
            LegacyAddressPayloadCodec.TryWrite([first, second], encoded, out _));

        Span<LegacyAddressRecord> destination = stackalloc LegacyAddressRecord[1];
        destination[0] = first;
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            LegacyAddressPayloadCodec.TryParse(encoded, destination, out var recordsWritten, out var bytesConsumed));
        Assert.AreEqual(0, recordsWritten);
        Assert.AreEqual(0, bytesConsumed);
        Assert.AreEqual(first, destination[0]);

        var tooMany = new LegacyAddressRecord[LegacyAddressPayloadCodec.MaximumRecordCount + 1];
        Span<byte> untouched = stackalloc byte[LegacyAddressPayloadCodec.MaximumPayloadLength];
        untouched.Fill(0xa5);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            LegacyAddressPayloadCodec.TryWrite(tooMany, untouched, out var bytesWritten));
        Assert.AreEqual(0, bytesWritten);
        Assert.IsTrue(untouched.IndexOfAnyExcept((byte)0xa5) < 0);

        Span<byte> tooSmall = stackalloc byte[encoded.Length - 1];
        tooSmall.Fill(0xa5);
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            LegacyAddressPayloadCodec.TryWrite([first, second], tooSmall, out bytesWritten));
        Assert.AreEqual(0, bytesWritten);
        Assert.IsTrue(tooSmall.IndexOfAnyExcept((byte)0xa5) < 0);
    }

    [TestMethod]
    public void MaximumPayloadHasNoWarmAllocationOrCountSlope()
    {
        var records = new LegacyAddressRecord[LegacyAddressPayloadCodec.MaximumRecordCount];
        for (var index = 0; index < records.Length; index++)
        {
            records[index] = CreateIpv4Record(
                (uint)index,
                [198, 51, 100, (byte)index],
                checked((ushort)(8_000 + index)));
        }

        var payload = new byte[LegacyAddressPayloadCodec.MaximumPayloadLength];
        Assert.AreEqual(
            OperationStatus.Done,
            LegacyAddressPayloadCodec.TryWrite(records, payload, out var bytesWritten));
        Assert.AreEqual(payload.Length, bytesWritten);
        var destination = new LegacyAddressRecord[records.Length];
        Assert.IsTrue(ParseMaximum(payload, destination));

        var before = GC.GetAllocatedBytesForCurrentThread();
        var succeeded = ParseMaximum(payload, destination);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.IsTrue(succeeded);
        Assert.AreEqual(0L, allocated);
        Assert.AreEqual(records[^1], destination[^1]);
    }

    private static bool ParseMaximum(byte[] payload, LegacyAddressRecord[] destination) =>
        LegacyAddressPayloadCodec.TryParse(
            payload,
            destination,
            out var recordsWritten,
            out var bytesConsumed) == OperationStatus.Done &&
        recordsWritten == LegacyAddressPayloadCodec.MaximumRecordCount &&
        bytesConsumed == payload.Length;

    private static LegacyAddressRecord CreateIpv4Record(
        uint timestamp,
        ReadOnlySpan<byte> addressBytes,
        ushort port)
    {
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, addressBytes, port, out var address));
        return new LegacyAddressRecord(timestamp, address);
    }

    private static void AssertParseFailure(ReadOnlySpan<byte> payload, OperationStatus expected)
    {
        Span<LegacyAddressRecord> destination = stackalloc LegacyAddressRecord[LegacyAddressPayloadCodec.MaximumRecordCount];
        Assert.AreEqual(
            expected,
            LegacyAddressPayloadCodec.TryParse(payload, destination, out var recordsWritten, out var bytesConsumed));
        Assert.AreEqual(0, recordsWritten);
        Assert.AreEqual(0, bytesConsumed);
    }
}
