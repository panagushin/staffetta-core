using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Blocks;

namespace Staffetta.Core.Tests.Protocol.Blocks;

[TestClass]
public sealed class BlockHeaderCodecTests
{
    private const string FixtureFileName = "headers-mainnet-after-genesis-2000-20260830.bin";
    private const string GenesisBlockId =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    private const string ExpectedFirstBlockId =
        "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048";

    [TestMethod]
    public void CapturedFirstHeaderParsesHashesAndRoundTrips()
    {
        var payload = File.ReadAllBytes(GetFixturePath(FixtureFileName));
        var encodedHeader = payload.AsSpan(3, BlockHeaderCodec.EncodedLength);

        var parseStatus = BlockHeaderCodec.TryParse(encodedHeader, out var header, out var bytesConsumed);

        Assert.AreEqual(OperationStatus.Done, parseStatus);
        Assert.AreEqual(BlockHeaderCodec.EncodedLength, bytesConsumed);
        Assert.AreEqual(1, header.Version);
        Assert.AreEqual(GenesisBlockId, header.PreviousBlockHash.ToDisplayHex());
        Assert.AreEqual<uint>(1_231_469_665, header.Timestamp);
        Assert.AreEqual<uint>(0x1d00ffff, header.Bits);
        Assert.AreEqual<uint>(2_573_394_689, header.Nonce);
        Assert.AreEqual(ExpectedFirstBlockId, header.ComputeHash().ToDisplayHex());

        Span<byte> encoded = stackalloc byte[BlockHeaderCodec.EncodedLength];
        Assert.AreEqual(
            OperationStatus.Done,
            BlockHeaderCodec.TryWrite(encoded, header, out var bytesWritten));
        Assert.AreEqual(BlockHeaderCodec.EncodedLength, bytesWritten);
        Assert.IsTrue(encoded.SequenceEqual(encodedHeader));
    }

    [TestMethod]
    public void ParseAndWriteReportIncompleteDestinationsWithoutConsumption()
    {
        for (var length = 0; length < BlockHeaderCodec.EncodedLength; length++)
        {
            Assert.AreEqual(
                OperationStatus.NeedMoreData,
                BlockHeaderCodec.TryParse(new byte[length], out _, out var bytesConsumed));
            Assert.AreEqual(0, bytesConsumed);
        }

        Assert.AreEqual(
            OperationStatus.Done,
            BlockHeaderCodec.TryParse(new byte[BlockHeaderCodec.EncodedLength], out var header, out _));

        for (var length = 0; length < BlockHeaderCodec.EncodedLength; length++)
        {
            var destination = new byte[length];
            Array.Fill(destination, (byte)0xa5);

            Assert.AreEqual(
                OperationStatus.DestinationTooSmall,
                BlockHeaderCodec.TryWrite(destination, header, out var bytesWritten));
            Assert.AreEqual(0, bytesWritten);
            Assert.IsTrue(destination.AsSpan().IndexOfAnyExcept((byte)0xa5) < 0);
        }
    }

    private static string GetFixturePath(string fileName) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "Bsv", fileName);
}
