using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Encoding;

namespace Staffetta.Core.Tests.Protocol.Encoding;

[TestClass]
public sealed class CompactSizeTests
{
    [TestMethod]
    public void ReadAcceptsCanonicalBoundaryEncodings()
    {
        AssertReadDone(0, [0x00]);
        AssertReadDone(0xfc, [0xfc]);
        AssertReadDone(0xfd, [0xfd, 0xfd, 0x00]);
        AssertReadDone(ushort.MaxValue, [0xfd, 0xff, 0xff]);
        AssertReadDone(0x1_0000, [0xfe, 0x00, 0x00, 0x01, 0x00]);
        AssertReadDone(uint.MaxValue, [0xfe, 0xff, 0xff, 0xff, 0xff]);
        AssertReadDone(
            0x1_0000_0000,
            [0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        AssertReadDone(
            ulong.MaxValue,
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    }

    [TestMethod]
    public void ReadConsumesOnlyOneValue()
    {
        ReadOnlySpan<byte> source = [0xfd, 0xfd, 0x00, 0xa5];

        var status = CompactSize.Read(source, out var value, out var bytesConsumed);

        Assert.AreEqual(OperationStatus.Done, status);
        Assert.AreEqual<ulong>(0xfd, value);
        Assert.AreEqual(3, bytesConsumed);
    }

    [TestMethod]
    public void ReadRejectsTruncatedEncodingsWithoutConsumption()
    {
        AssertReadTruncated([]);
        AssertPrefixTruncations(0xfd, 3);
        AssertPrefixTruncations(0xfe, 5);
        AssertPrefixTruncations(0xff, 9);
    }

    [TestMethod]
    public void ReadRejectsNonCanonicalEncodingsWithoutConsumption()
    {
        AssertReadInvalid([0xfd, 0x00, 0x00]);
        AssertReadInvalid([0xfd, 0xfc, 0x00]);
        AssertReadInvalid([0xfe, 0xfd, 0x00, 0x00, 0x00]);
        AssertReadInvalid([0xfe, 0xff, 0xff, 0x00, 0x00]);
        AssertReadInvalid([0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
        AssertReadInvalid([0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);
    }

    [TestMethod]
    public void WriteProducesCanonicalBoundaryEncodings()
    {
        AssertWriteDone(0, [0x00]);
        AssertWriteDone(0xfc, [0xfc]);
        AssertWriteDone(0xfd, [0xfd, 0xfd, 0x00]);
        AssertWriteDone(ushort.MaxValue, [0xfd, 0xff, 0xff]);
        AssertWriteDone(0x1_0000, [0xfe, 0x00, 0x00, 0x01, 0x00]);
        AssertWriteDone(uint.MaxValue, [0xfe, 0xff, 0xff, 0xff, 0xff]);
        AssertWriteDone(
            0x1_0000_0000,
            [0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        AssertWriteDone(
            ulong.MaxValue,
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    }

    [TestMethod]
    public void WriteReportsDestinationTooSmallWithoutWriting()
    {
        AssertWriteTooSmall(0xfc, 1);
        AssertWriteTooSmall(0xfd, 3);
        AssertWriteTooSmall(0x1_0000, 5);
        AssertWriteTooSmall(0x1_0000_0000, 9);
    }

    private static void AssertPrefixTruncations(byte prefix, int encodedLength)
    {
        var source = new byte[encodedLength];
        Array.Fill(source, byte.MaxValue);
        source[0] = prefix;

        for (var length = 1; length < encodedLength; length++)
        {
            AssertReadTruncated(source.AsSpan(0, length));
        }
    }

    private static void AssertReadDone(ulong expectedValue, byte[] encoding)
    {
        var status = CompactSize.Read(encoding, out var value, out var bytesConsumed);

        Assert.AreEqual(OperationStatus.Done, status);
        Assert.AreEqual(expectedValue, value);
        Assert.AreEqual(encoding.Length, bytesConsumed);
    }

    private static void AssertReadTruncated(ReadOnlySpan<byte> source)
    {
        var status = CompactSize.Read(source, out var value, out var bytesConsumed);

        Assert.AreEqual(OperationStatus.NeedMoreData, status);
        Assert.AreEqual<ulong>(0, value);
        Assert.AreEqual(0, bytesConsumed);
    }

    private static void AssertReadInvalid(ReadOnlySpan<byte> source)
    {
        var status = CompactSize.Read(source, out var value, out var bytesConsumed);

        Assert.AreEqual(OperationStatus.InvalidData, status);
        Assert.AreEqual<ulong>(0, value);
        Assert.AreEqual(0, bytesConsumed);
    }

    private static void AssertWriteDone(ulong value, byte[] expectedEncoding)
    {
        var destination = new byte[expectedEncoding.Length];

        var status = CompactSize.Write(value, destination, out var bytesWritten);

        Assert.AreEqual(OperationStatus.Done, status);
        Assert.AreEqual(expectedEncoding.Length, bytesWritten);
        CollectionAssert.AreEqual(expectedEncoding, destination);
    }

    private static void AssertWriteTooSmall(ulong value, int encodedLength)
    {
        for (var length = 0; length < encodedLength; length++)
        {
            var destination = new byte[length];
            Array.Fill(destination, (byte)0xa5);

            var status = CompactSize.Write(value, destination, out var bytesWritten);

            Assert.AreEqual(OperationStatus.DestinationTooSmall, status);
            Assert.AreEqual(0, bytesWritten);
            Assert.IsTrue(destination.AsSpan().IndexOfAnyExcept((byte)0xa5) < 0);
        }
    }
}
