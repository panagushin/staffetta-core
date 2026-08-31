using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Tests.Protocol.Cryptography;

[TestClass]
public sealed class Hash256Tests
{
    [TestMethod]
    public void WireBytesRoundTripWithoutChangingDisplayOrder()
    {
        var wireBytes = Enumerable.Range(0, Hash256.Length).Select(value => (byte)value).ToArray();

        Assert.AreEqual(OperationStatus.Done, Hash256.TryCreate(wireBytes, out var hash));
        Assert.AreEqual(
            "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
            hash.ToDisplayHex());

        Span<byte> copiedWireBytes = stackalloc byte[Hash256.Length];
        Assert.AreEqual(
            OperationStatus.Done,
            hash.TryCopyWireBytesTo(copiedWireBytes, out var bytesWritten));
        Assert.AreEqual(Hash256.Length, bytesWritten);
        Assert.IsTrue(copiedWireBytes.SequenceEqual(wireBytes));
    }

    [TestMethod]
    public void InvalidLengthsDoNotCreateOrCopyHashes()
    {
        Assert.AreEqual(OperationStatus.InvalidData, Hash256.TryCreate([], out var hash));
        Assert.AreEqual(default, hash);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            Hash256.TryCreate(new byte[Hash256.Length + 1], out hash));
        Assert.AreEqual(default, hash);

        for (var length = 0; length < Hash256.Length; length++)
        {
            var destination = new byte[length];
            Array.Fill(destination, (byte)0xa5);

            Assert.AreEqual(
                OperationStatus.DestinationTooSmall,
                hash.TryCopyWireBytesTo(destination, out var bytesWritten));
            Assert.AreEqual(0, bytesWritten);
            Assert.IsTrue(destination.AsSpan().IndexOfAnyExcept((byte)0xa5) < 0);
        }
    }
}
