using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Blocks;

namespace Staffetta.Core.Tests.Protocol.Blocks;

[TestClass]
public sealed class HeadersPayloadCodecTests
{
    private const string FixtureFileName = "headers-mainnet-after-genesis-2000-20260830.bin";
    private const string GenesisBlockId =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    private const string ExpectedFirstBlockId =
        "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048";
    private const string ExpectedLastBlockId =
        "00000000dfd5d65c9d8561b4b8f60a63018fe3933ecb131fb37f905f87da951a";

    [TestMethod]
    public void CapturedMainnetPayloadParsesThroughProductionCodec()
    {
        var payload = File.ReadAllBytes(GetFixturePath(FixtureFileName));
        var headers = new BlockHeader[HeadersPayloadCodec.MaximumHeaderCount];

        var status = HeadersPayloadCodec.TryParse(payload, headers, out var headersWritten);

        Assert.AreEqual(OperationStatus.Done, status);
        Assert.AreEqual(HeadersPayloadCodec.MaximumHeaderCount, headersWritten);
        Assert.AreEqual(GenesisBlockId, headers[0].PreviousBlockHash.ToDisplayHex());
        Assert.AreEqual(ExpectedFirstBlockId, headers[0].ComputeHash().ToDisplayHex());
        Assert.AreEqual(ExpectedLastBlockId, headers[^1].ComputeHash().ToDisplayHex());

        var expectedPreviousHash = headers[0].ComputeHash();
        for (var index = 1; index < headers.Length; index++)
        {
            Assert.AreEqual(expectedPreviousHash, headers[index].PreviousBlockHash, $"Header {index}");
            expectedPreviousHash = headers[index].ComputeHash();
        }
    }

    [TestMethod]
    public void EmptyAndSyntheticPayloadsRoundTrip()
    {
        Span<BlockHeader> emptyHeaders = [];
        Span<byte> emptyPayload = stackalloc byte[1];
        Assert.AreEqual(
            OperationStatus.Done,
            HeadersPayloadCodec.TryWrite(emptyHeaders, emptyPayload, out var emptyBytesWritten));
        Assert.AreEqual(1, emptyBytesWritten);
        Assert.AreEqual((byte)0, emptyPayload[0]);
        Assert.AreEqual(
            OperationStatus.Done,
            HeadersPayloadCodec.TryParse(emptyPayload, emptyHeaders, out var emptyHeadersWritten));
        Assert.AreEqual(0, emptyHeadersWritten);

        var fixturePayload = File.ReadAllBytes(GetFixturePath(FixtureFileName));
        Span<BlockHeader> sourceHeaders = new BlockHeader[2];
        Assert.AreEqual(
            OperationStatus.DestinationTooSmall,
            HeadersPayloadCodec.TryParse(fixturePayload, sourceHeaders, out _));

        var allHeaders = new BlockHeader[HeadersPayloadCodec.MaximumHeaderCount];
        Assert.AreEqual(
            OperationStatus.Done,
            HeadersPayloadCodec.TryParse(fixturePayload, allHeaders, out _));
        sourceHeaders[0] = allHeaders[0];
        sourceHeaders[1] = allHeaders[1];

        var encoded = new byte[1 + (sourceHeaders.Length * 81)];
        Assert.AreEqual(
            OperationStatus.Done,
            HeadersPayloadCodec.TryWrite(sourceHeaders, encoded, out var bytesWritten));
        Assert.AreEqual(encoded.Length, bytesWritten);

        Span<BlockHeader> parsedHeaders = new BlockHeader[2];
        Assert.AreEqual(
            OperationStatus.Done,
            HeadersPayloadCodec.TryParse(encoded, parsedHeaders, out var headersWritten));
        Assert.AreEqual(2, headersWritten);
        Assert.IsTrue(sourceHeaders.SequenceEqual(parsedHeaders));
    }

    [TestMethod]
    public void ParseRejectsInvalidCountsRecordMarkersAndTrailingBytes()
    {
        Assert.AreEqual(
            OperationStatus.InvalidData,
            HeadersPayloadCodec.TryParse([0xfd, 0xd1, 0x07], new BlockHeader[2_001], out _));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            HeadersPayloadCodec.TryParse([0xfd, 0x00, 0x00], [], out _));

        var oneHeaderPayload = GetOneHeaderPayload();
        oneHeaderPayload[1 + BlockHeaderCodec.EncodedLength] = 1;
        var destination = new BlockHeader[1];
        Assert.AreEqual(
            OperationStatus.Done,
            BlockHeaderCodec.TryParse(
                File.ReadAllBytes(GetFixturePath(FixtureFileName)).AsSpan(3),
                out destination[0],
                out _));
        var originalDestination = destination[0];
        Assert.AreEqual(
            OperationStatus.InvalidData,
            HeadersPayloadCodec.TryParse(oneHeaderPayload, destination, out var invalidHeadersWritten));
        Assert.AreEqual(0, invalidHeadersWritten);
        Assert.AreEqual(originalDestination, destination[0]);

        oneHeaderPayload[1 + BlockHeaderCodec.EncodedLength] = 0;
        Array.Resize(ref oneHeaderPayload, oneHeaderPayload.Length + 1);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            HeadersPayloadCodec.TryParse(oneHeaderPayload, new BlockHeader[1], out _));
    }

    [TestMethod]
    public void ParseReportsNeedMoreDataForTruncatedBoundedPayload()
    {
        var oneHeaderPayload = GetOneHeaderPayload();

        for (var length = 1; length < 1 + 81; length++)
        {
            Assert.AreEqual(
                OperationStatus.NeedMoreData,
                HeadersPayloadCodec.TryParse(
                    oneHeaderPayload.AsSpan(0, length),
                    new BlockHeader[1],
                    out var headersWritten),
                $"Length {length}");
            Assert.AreEqual(0, headersWritten, $"Length {length}");
        }
    }

    private static string GetFixturePath(string fileName) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "Bsv", fileName);

    private static byte[] GetOneHeaderPayload()
    {
        var fixturePayload = File.ReadAllBytes(GetFixturePath(FixtureFileName));
        var payload = new byte[1 + BlockHeaderCodec.EncodedLength + 1];
        payload[0] = 1;
        fixturePayload.AsSpan(3, BlockHeaderCodec.EncodedLength + 1).CopyTo(payload.AsSpan(1));
        return payload;
    }
}
