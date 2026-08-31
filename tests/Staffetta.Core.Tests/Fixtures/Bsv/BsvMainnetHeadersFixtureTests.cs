using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Encoding;

namespace Staffetta.Core.Tests.Fixtures.Bsv;

[TestClass]
public sealed class BsvMainnetHeadersFixtureTests
{
    private const string FixtureBaseName = "headers-mainnet-after-genesis-2000-20260830";
    private const string ExpectedSchema = "staffetta-bsv-headers-fixture/v1";
    private const string ExpectedPayloadSha256 =
        "6f08960bc229c31ea566304ec9ac9bc88d36192b33f6ee8055058743b5a25d52";
    private const int ExpectedPayloadByteLength = 162_003;
    private const int ExpectedHeaderCount = 2_000;
    private const int HeaderLength = 80;
    private const int PreviousBlockHashOffset = 4;
    private const int HashLength = 32;
    private const string GenesisBlockId =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    private const string ExpectedFirstBlockId =
        "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048";
    private const string ExpectedLastBlockId =
        "00000000dfd5d65c9d8561b4b8f60a63018fe3933ecb131fb37f905f87da951a";

    private static ReadOnlySpan<byte> CanonicalHeaderCount => [0xfd, 0xd0, 0x07];

    [TestMethod]
    public void CapturedHeadersHaveBoundProvenanceAndCanonicalLinkedRecords()
    {
        FixtureMetadata metadata = LoadMetadata();
        AssertProvenance(metadata);

        byte[] payload = File.ReadAllBytes(GetFixturePath(metadata.PayloadFile));
        Assert.AreEqual(ExpectedPayloadByteLength, payload.Length);
        Assert.AreEqual(ExpectedPayloadSha256, ComputeSha256(payload));

        Assert.AreEqual(
            OperationStatus.Done,
            CompactSize.Read(payload, out ulong headerCount, out int bytesConsumed));
        Assert.AreEqual<ulong>(ExpectedHeaderCount, headerCount);
        Assert.AreEqual(3, bytesConsumed);
        Assert.IsTrue(payload.AsSpan(0, bytesConsumed).SequenceEqual(CanonicalHeaderCount));

        byte[] expectedPreviousHash = FromDisplayBlockId(GenesisBlockId);
        string? firstBlockId = null;
        string? lastBlockId = null;
        int offset = bytesConsumed;

        for (var index = 0; index < ExpectedHeaderCount; index++)
        {
            Assert.IsTrue(
                payload.Length - offset >= HeaderLength + 1,
                $"Header record {index} is truncated.");

            ReadOnlySpan<byte> header = payload.AsSpan(offset, HeaderLength);
            Assert.IsTrue(
                header.Slice(PreviousBlockHashOffset, HashLength).SequenceEqual(expectedPreviousHash),
                $"Header record {index} does not link to its expected predecessor.");
            offset += HeaderLength;

            Assert.AreEqual(0, payload[offset], $"Header record {index} has a non-zero transaction count.");
            offset++;

            expectedPreviousHash = DoubleSha256(header);
            string blockId = ToDisplayBlockId(expectedPreviousHash);
            firstBlockId ??= blockId;
            lastBlockId = blockId;
        }

        Assert.AreEqual(payload.Length, offset, "Fixture has trailing bytes after 2,000 header records.");
        Assert.AreEqual(ExpectedFirstBlockId, firstBlockId);
        Assert.AreEqual(ExpectedLastBlockId, lastBlockId);
    }

    private static void AssertProvenance(FixtureMetadata metadata)
    {
        Assert.AreEqual(ExpectedSchema, metadata.Schema);
        Assert.AreEqual(FixtureBaseName + ".bin", metadata.PayloadFile);
        Assert.AreEqual(ExpectedPayloadSha256, metadata.PayloadSha256);
        Assert.AreEqual(ExpectedPayloadByteLength, metadata.PayloadByteLength);
        Assert.AreEqual("2026-08-30T23:12:49Z", metadata.CapturedAtUtc);
        Assert.AreEqual("57.129.76.3:8333", metadata.PeerEndpoint);
        Assert.AreEqual("/Bitcoin SV:1.2.2/", metadata.PeerUserAgent);
        Assert.AreEqual(70_015, metadata.CaptureProtocolVersion);
        Assert.AreEqual("getheaders", metadata.RequestCommand);
        Assert.AreEqual(GenesisBlockId, metadata.LocatorBlockId);
        Assert.AreEqual(ExpectedHeaderCount, metadata.HeaderCount);
        Assert.AreEqual(ExpectedFirstBlockId, metadata.FirstBlockId);
        Assert.AreEqual(ExpectedLastBlockId, metadata.LastBlockId);
        Assert.IsTrue(metadata.Validates.CanonicalCount);
        Assert.IsTrue(metadata.Validates.RecordFraming);
        Assert.IsTrue(metadata.Validates.GenesisAnchor);
        Assert.IsTrue(metadata.Validates.InternalLinkage);
        Assert.IsFalse(
            metadata.Validates.DifficultyAdjustmentAlgorithm,
            "This operational fixture does not validate BSV DAA consensus rules.");
    }

    private static FixtureMetadata LoadMetadata()
    {
        string json = File.ReadAllText(GetFixturePath(FixtureBaseName + ".json"));
        return JsonSerializer.Deserialize<FixtureMetadata>(json)
            ?? throw new InvalidDataException("Fixture metadata deserialized to null.");
    }

    private static string GetFixturePath(string fileName) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "Bsv", fileName);

    private static string ComputeSha256(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

    private static byte[] DoubleSha256(ReadOnlySpan<byte> value)
    {
        Span<byte> firstHash = stackalloc byte[HashLength];
        byte[] secondHash = new byte[HashLength];
        SHA256.HashData(value, firstHash);
        SHA256.HashData(firstHash, secondHash);
        return secondHash;
    }

    private static byte[] FromDisplayBlockId(string blockId)
    {
        byte[] wireOrder = Convert.FromHexString(blockId);
        Array.Reverse(wireOrder);
        return wireOrder;
    }

    private static string ToDisplayBlockId(ReadOnlySpan<byte> wireOrderHash)
    {
        byte[] displayOrder = wireOrderHash.ToArray();
        Array.Reverse(displayOrder);
        return Convert.ToHexString(displayOrder).ToLowerInvariant();
    }

    private sealed record FixtureMetadata(
        string Schema,
        string PayloadFile,
        string PayloadSha256,
        int PayloadByteLength,
        string CapturedAtUtc,
        string PeerEndpoint,
        string PeerUserAgent,
        int CaptureProtocolVersion,
        string RequestCommand,
        string LocatorBlockId,
        int HeaderCount,
        string FirstBlockId,
        string LastBlockId,
        ValidationScope Validates);

    private sealed record ValidationScope(
        bool CanonicalCount,
        bool RecordFraming,
        bool GenesisAnchor,
        bool InternalLinkage,
        bool DifficultyAdjustmentAlgorithm);
}
