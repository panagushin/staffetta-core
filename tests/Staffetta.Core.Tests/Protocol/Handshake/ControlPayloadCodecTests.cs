using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Handshake;

namespace Staffetta.Core.Tests.Protocol.Handshake;

[TestClass]
public sealed class ControlPayloadCodecTests
{
    [TestMethod]
    public void VerackIsStrictlyEmpty()
    {
        Assert.AreEqual(OperationStatus.Done, VerackPayloadCodec.TryParse([]));
        Assert.AreEqual(OperationStatus.InvalidData, VerackPayloadCodec.TryParse([0]));
        Assert.AreEqual(
            OperationStatus.Done,
            VerackPayloadCodec.TryWrite(Span<byte>.Empty, out var bytesWritten));
        Assert.AreEqual(0, bytesWritten);
    }

    [TestMethod]
    public void ModernPingAndPongNonceIsStrictlyEightLittleEndianBytes()
    {
        const ulong nonce = 0x1122_3344_5566_7788;
        Span<byte> encoded = stackalloc byte[ModernPingPongPayloadCodec.EncodedLength];
        Assert.AreEqual(
            OperationStatus.Done,
            ModernPingPongPayloadCodec.TryWrite(encoded, nonce, out var bytesWritten));
        Assert.AreEqual(ModernPingPongPayloadCodec.EncodedLength, bytesWritten);
        Assert.IsTrue(encoded.SequenceEqual(new byte[] { 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 }));
        Assert.AreEqual(OperationStatus.Done, ModernPingPongPayloadCodec.TryParse(encoded, out var parsed));
        Assert.AreEqual(nonce, parsed);

        for (var length = 0; length < ModernPingPongPayloadCodec.EncodedLength; length++)
        {
            Assert.AreEqual(
                OperationStatus.NeedMoreData,
                ModernPingPongPayloadCodec.TryParse(encoded[..length], out _));

            var destination = new byte[length];
            Array.Fill(destination, (byte)0xa5);
            Assert.AreEqual(
                OperationStatus.DestinationTooSmall,
                ModernPingPongPayloadCodec.TryWrite(destination, nonce, out bytesWritten));
            Assert.AreEqual(0, bytesWritten);
            Assert.IsTrue(destination.AsSpan().IndexOfAnyExcept((byte)0xa5) < 0);
        }

        Span<byte> oversized = stackalloc byte[ModernPingPongPayloadCodec.EncodedLength + 1];
        Assert.AreEqual(OperationStatus.InvalidData, ModernPingPongPayloadCodec.TryParse(oversized, out _));
    }
}
