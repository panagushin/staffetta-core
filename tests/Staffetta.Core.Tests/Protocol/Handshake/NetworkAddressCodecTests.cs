using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Handshake;

namespace Staffetta.Core.Tests.Protocol.Handshake;

[TestClass]
public sealed class NetworkAddressCodecTests
{
    [TestMethod]
    public void Ipv4MappedAddressRoundTripsWithRawServicesAndBigEndianPort()
    {
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(
            0xfedc_ba98_7654_3210,
            [192, 0, 2, 1],
            8_333,
            out var address));

        Span<byte> encoded = stackalloc byte[NetworkAddressCodec.EncodedLength];
        Assert.AreEqual(
            OperationStatus.Done,
            NetworkAddressCodec.TryWrite(encoded, address, out var bytesWritten));

        Assert.AreEqual(NetworkAddressCodec.EncodedLength, bytesWritten);
        Assert.IsTrue(encoded[..8].SequenceEqual(new byte[] { 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe }));
        Assert.IsTrue(encoded.Slice(8, 12).SequenceEqual(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff }));
        Assert.IsTrue(encoded.Slice(20, 4).SequenceEqual(new byte[] { 192, 0, 2, 1 }));
        Assert.IsTrue(encoded[24..].SequenceEqual(new byte[] { 0x20, 0x8d }));

        Assert.AreEqual(
            OperationStatus.Done,
            NetworkAddressCodec.TryParse(encoded, out var parsed, out var bytesConsumed));
        Assert.AreEqual(NetworkAddressCodec.EncodedLength, bytesConsumed);
        Assert.AreEqual(address, parsed);
        Assert.IsTrue(parsed.IsIpv4Mapped);

        Span<byte> ipv4 = stackalloc byte[4];
        Assert.IsTrue(parsed.TryWriteIpv4(ipv4));
        Assert.IsTrue(ipv4.SequenceEqual(new byte[] { 192, 0, 2, 1 }));
    }

    [TestMethod]
    public void ParseAndWriteReportEveryIncompleteLengthWithoutMutation()
    {
        var address = new NetworkAddress(1, new byte[16], 1);
        for (var length = 0; length < NetworkAddressCodec.EncodedLength; length++)
        {
            Assert.AreEqual(
                OperationStatus.NeedMoreData,
                NetworkAddressCodec.TryParse(new byte[length], out _, out var bytesConsumed));
            Assert.AreEqual(0, bytesConsumed);

            var destination = new byte[length];
            Array.Fill(destination, (byte)0xa5);
            Assert.AreEqual(
                OperationStatus.DestinationTooSmall,
                NetworkAddressCodec.TryWrite(destination, address, out var bytesWritten));
            Assert.AreEqual(0, bytesWritten);
            Assert.IsTrue(destination.AsSpan().IndexOfAnyExcept((byte)0xa5) < 0);
        }
    }

    [TestMethod]
    public void NonMappedIpv6DoesNotProduceIpv4Bytes()
    {
        var address = new NetworkAddress(0, [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 8333);

        Span<byte> destination = stackalloc byte[4];
        Assert.IsFalse(address.IsIpv4Mapped);
        Assert.IsFalse(address.TryWriteIpv4(destination));
    }
}
