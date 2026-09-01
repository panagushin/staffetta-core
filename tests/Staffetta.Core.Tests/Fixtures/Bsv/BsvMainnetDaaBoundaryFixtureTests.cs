using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Encoding;

namespace Staffetta.Core.Tests.Fixtures.Bsv;

[TestClass]
public sealed class BsvMainnetDaaBoundaryFixtureTests
{
    private const string FixtureBaseName = "headers-mainnet-daa-boundary-503885-504032-20260901";
    private const string ExpectedSchema = "staffetta-bsv-daa-boundary-fixture/v1";
    private const string ExpectedPayloadSha256 =
        "80e12a5c4616b1f1f38e29bfeff02c9ba0813cb2d6427d0efd5032fb4b7f05a0";
    private const int ExpectedPayloadByteLength = 11_989;
    private const int ExpectedHeaderCount = 148;
    private const int FirstHeight = 503_885;
    private const int LastHeight = 504_032;
    private const string AnchorBlockId =
        "00000000000000000776fb6d883320aee713c40ac31f7ba8fb90cae0d705b262";
    private const string ExpectedFirstBlockId =
        "000000000000000004384022a14090241319ed8999767e1371c339a4149becda";
    private const string ExpectedDaaCheckpointBlockId =
        "0000000000000000011ebf65b60d0a3de80b8175be709d653b4c1a1beeb6ab9c";
    private const string ExpectedLastBlockId =
        "00000000000000000343e9875012f2062554c8752929892c82a0c0743ac7dcfd";
    private const string FullBatchSha256 =
        "0531a7428367a28822e9234acead8de7b132c7630c15c55d0b259719d5fc4969";

    [TestMethod]
    public void BoundaryHeadersHaveReproducibleProvenanceFramingLinkageAndProofOfWork()
    {
        FixtureMetadata metadata = LoadMetadata();
        AssertMetadata(metadata);

        byte[] payload = File.ReadAllBytes(GetFixturePath(metadata.PayloadFile));
        Assert.AreEqual(ExpectedPayloadByteLength, payload.Length);
        Assert.AreEqual(ExpectedPayloadSha256, ComputeSha256(payload));
        Assert.AreEqual(
            OperationStatus.Done,
            CompactSize.Read(payload, out ulong compactCount, out int countLength));
        Assert.AreEqual<ulong>(ExpectedHeaderCount, compactCount);
        Assert.AreEqual(1, countLength);
        Assert.AreEqual(0x94, payload[0]);
        Assert.AreEqual(
            countLength + (ExpectedHeaderCount * (BlockHeaderCodec.EncodedLength + 1)),
            payload.Length);

        var headers = new BlockHeader[ExpectedHeaderCount];
        Assert.AreEqual(
            OperationStatus.Done,
            HeadersPayloadCodec.TryParse(payload, headers, out int headerCount));
        Assert.AreEqual(ExpectedHeaderCount, headerCount);
        Assert.AreEqual(AnchorBlockId, headers[0].PreviousBlockHash.ToDisplayHex());

        var proofOfWorkLimit = CompactTarget.Decode(0x1d00ffff).Value;
        Span<BlockDifficultyContext> daaContext =
            stackalloc BlockDifficultyContext[BsvMainnetDifficultyAdjustment.RequiredContextLength];
        UInt256 cumulativeWork = UInt256.Zero;
        string? firstBlockId = null;
        string? lastBlockId = null;
        for (var index = 0; index < headerCount; index++)
        {
            string blockId = headers[index].ComputeHash().ToDisplayHex();
            if (index > 0)
            {
                Assert.AreEqual(
                    headers[index - 1].ComputeHash(),
                    headers[index].PreviousBlockHash,
                    $"Header at height {FirstHeight + index} does not link to its predecessor.");
            }

            Assert.AreEqual(
                BlockProofOfWorkValidation.Valid,
                BlockProofOfWork.Validate(headers[index], proofOfWorkLimit),
                $"Header at height {FirstHeight + index} failed claimed-target proof-of-work.");
            if (index < daaContext.Length)
            {
                cumulativeWork = cumulativeWork.Add(BlockProofOfWork.GetBlockWork(headers[index].Bits));
                daaContext[index] = new BlockDifficultyContext(
                    FirstHeight + index,
                    headers[index].Timestamp,
                    cumulativeWork);
            }

            firstBlockId ??= blockId;
            lastBlockId = blockId;
        }

        Assert.AreEqual(ExpectedFirstBlockId, firstBlockId);
        Assert.AreEqual(ExpectedDaaCheckpointBlockId, headers[504_031 - FirstHeight].ComputeHash().ToDisplayHex());
        Assert.AreEqual(ExpectedLastBlockId, headers[504_032 - FirstHeight].ComputeHash().ToDisplayHex());
        Assert.AreEqual(ExpectedLastBlockId, lastBlockId);
        Assert.AreEqual(
            DifficultyAdjustmentCalculationStatus.Done,
            BsvMainnetDifficultyAdjustment.CalculateNextBits(
                daaContext,
                proofOfWorkLimit,
                out uint expectedCompactTarget));
        Assert.AreEqual<uint>(0x1805b42b, expectedCompactTarget);
        Assert.AreEqual(expectedCompactTarget, headers[504_032 - FirstHeight].Bits);
    }

    private static void AssertMetadata(FixtureMetadata metadata)
    {
        Assert.AreEqual(ExpectedSchema, metadata.Schema);
        Assert.AreEqual(FixtureBaseName + ".bin", metadata.PayloadFile);
        Assert.AreEqual(ExpectedPayloadSha256, metadata.PayloadSha256);
        Assert.AreEqual(ExpectedPayloadByteLength, metadata.PayloadByteLength);
        Assert.AreEqual("main", metadata.Network);
        Assert.AreEqual(FirstHeight, metadata.FirstHeight);
        Assert.AreEqual(LastHeight, metadata.LastHeight);
        Assert.AreEqual(ExpectedHeaderCount, metadata.HeaderCount);
        Assert.AreEqual(FirstHeight - 1, metadata.AnchorHeight);
        Assert.AreEqual(AnchorBlockId, metadata.AnchorBlockId);
        Assert.AreEqual(ExpectedFirstBlockId, metadata.FirstBlockId);
        Assert.AreEqual(ExpectedLastBlockId, metadata.LastBlockId);
        Assert.AreEqual(504_031, metadata.DaaCheckpointHeight);
        Assert.AreEqual(ExpectedDaaCheckpointBlockId, metadata.DaaCheckpointBlockId);
        Assert.AreEqual("cc1757ef090d36db4b77b9ba4d399eaf9d3e9337", metadata.StaffettaCommit);
        Assert.AreEqual("clean", metadata.StaffettaRepositoryState);
        Assert.AreEqual("7c3902115125c3e23a302664b6b77e29fd5ff71d", metadata.BitcoinSvCommit);

        Assert.AreEqual(13, metadata.Extraction.SourceHop);
        Assert.AreEqual(FullBatchSha256, metadata.Extraction.SourcePayloadSha256);
        Assert.AreEqual(162_003, metadata.Extraction.SourcePayloadByteLength);
        Assert.AreEqual(2_000, metadata.Extraction.SourceHeaderCount);
        Assert.AreEqual(1_326, metadata.Extraction.FirstRecordIndex);
        Assert.AreEqual(1_473, metadata.Extraction.LastRecordIndex);
        Assert.AreEqual(0, metadata.Extraction.RecordIndexBase);
        Assert.AreEqual("94", metadata.Extraction.CanonicalCountHex);
        Assert.AreEqual(
            ExpectedHeaderCount,
            metadata.Extraction.LastRecordIndex - metadata.Extraction.FirstRecordIndex + 1);

        Assert.IsTrue(metadata.FullBatchSha256Equal);
        Assert.AreEqual(2, metadata.SourceCaptures.Length);
        AssertCapture(
            metadata.SourceCaptures[0],
            "15.235.232.121:8333",
            "2026-09-01T19:45:55.374889+00:00",
            "2026-09-01T19:45:58.263962+00:00");
        AssertCapture(
            metadata.SourceCaptures[1],
            "135.181.137.155:8333",
            "2026-09-01T19:48:53.252043+00:00",
            "2026-09-01T19:48:53.975475+00:00");
        Assert.AreEqual(metadata.SourceCaptures[0].PayloadSha256, metadata.SourceCaptures[1].PayloadSha256);

        Assert.AreEqual(478_558, metadata.CheckpointSandwich.LowerHeight);
        Assert.AreEqual(
            "0000000000000000011865af4122fe3b144e2cbeea86142e8ff2fb4107352d43",
            metadata.CheckpointSandwich.LowerBlockId);
        Assert.AreEqual(530_359, metadata.CheckpointSandwich.UpperHeight);
        Assert.AreEqual(
            "0000000000000000011ada8bd08f46074f44a8f155396f43e38acf9501c49103",
            metadata.CheckpointSandwich.UpperBlockId);
        Assert.AreEqual(26, metadata.CheckpointSandwich.UpperSourceHop);
        Assert.AreEqual(1_800, metadata.CheckpointSandwich.UpperSourceRecordIndex);
        Assert.AreEqual(0, metadata.CheckpointSandwich.RecordIndexBase);

        Assert.AreEqual(26, metadata.PrimaryPath.Length);
        Assert.AreEqual(metadata.CheckpointSandwich.LowerBlockId, metadata.PrimaryPath[0].LocatorBlockId);
        for (var index = 0; index < metadata.PrimaryPath.Length; index++)
        {
            PathHop hop = metadata.PrimaryPath[index];
            Assert.AreEqual(index + 1, hop.Hop);
            Assert.AreEqual(64, hop.PayloadSha256.Length);
            Assert.AreEqual(32, Convert.FromHexString(hop.PayloadSha256).Length);
            Assert.AreEqual(32, Convert.FromHexString(hop.LocatorBlockId).Length);
            Assert.AreEqual(32, Convert.FromHexString(hop.LastBlockId).Length);
            if (index > 0)
            {
                Assert.AreEqual(metadata.PrimaryPath[index - 1].LastBlockId, hop.LocatorBlockId);
            }
        }

        Assert.AreEqual(FullBatchSha256, metadata.PrimaryPath[12].PayloadSha256);
        int upperHopFirstHeight = metadata.CheckpointSandwich.LowerHeight +
            ((metadata.CheckpointSandwich.UpperSourceHop - 1) * 2_000) + 1;
        Assert.AreEqual(
            metadata.CheckpointSandwich.UpperHeight,
            upperHopFirstHeight + metadata.CheckpointSandwich.UpperSourceRecordIndex);

        Assert.IsTrue(metadata.Validates.CanonicalCount);
        Assert.IsTrue(metadata.Validates.RecordFraming);
        Assert.IsTrue(metadata.Validates.Anchor);
        Assert.IsTrue(metadata.Validates.InternalLinkage);
        Assert.IsTrue(metadata.Validates.ClaimedTargetProofOfWork);
        Assert.IsTrue(metadata.Validates.IndependentFullBatchEquality);
        Assert.IsTrue(metadata.Validates.CheckpointSandwich);
        Assert.IsTrue(metadata.Validates.DifficultyAdjustmentAlgorithm);
    }

    private static void AssertCapture(
        SourceCapture capture,
        string endpoint,
        string startedUtc,
        string completedUtc)
    {
        Assert.AreEqual(endpoint, capture.Endpoint);
        Assert.AreEqual("/Bitcoin SV:1.2.2/", capture.PeerUserAgent);
        Assert.AreEqual(startedUtc, capture.StartedUtc);
        Assert.AreEqual(completedUtc, capture.CompletedUtc);
        Assert.AreEqual(
            "0000000000000000056ab7d4705ea0d2ee546e4bda717a92d079b9c147a97756",
            capture.LocatorBlockId);
        Assert.AreEqual(FullBatchSha256, capture.PayloadSha256);
        Assert.AreEqual(162_003, capture.PayloadByteLength);
        Assert.AreEqual(2_000, capture.HeaderCount);
        Assert.AreEqual(
            "0000000000000000046907970aa4d9b2434791544dce0b5432ada82e8b3cf1d9",
            capture.FirstBlockId);
        Assert.AreEqual(
            "00000000000000000675d8de195c61b7955c6cdb16f93347116831b0624f366f",
            capture.LastBlockId);
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

    private sealed record FixtureMetadata(
        string Schema,
        string PayloadFile,
        string PayloadSha256,
        int PayloadByteLength,
        string Network,
        int FirstHeight,
        int LastHeight,
        int HeaderCount,
        int AnchorHeight,
        string AnchorBlockId,
        string FirstBlockId,
        string LastBlockId,
        int DaaCheckpointHeight,
        string DaaCheckpointBlockId,
        string StaffettaCommit,
        string StaffettaRepositoryState,
        string BitcoinSvCommit,
        ExtractionMetadata Extraction,
        bool FullBatchSha256Equal,
        SourceCapture[] SourceCaptures,
        CheckpointSandwich CheckpointSandwich,
        PathHop[] PrimaryPath,
        ValidationScope Validates);

    private sealed record ExtractionMetadata(
        int SourceHop,
        string SourcePayloadSha256,
        int SourcePayloadByteLength,
        int SourceHeaderCount,
        int FirstRecordIndex,
        int LastRecordIndex,
        int RecordIndexBase,
        string CanonicalCountHex);

    private sealed record SourceCapture(
        string Endpoint,
        string PeerUserAgent,
        string StartedUtc,
        string CompletedUtc,
        string LocatorBlockId,
        string PayloadSha256,
        int PayloadByteLength,
        int HeaderCount,
        string FirstBlockId,
        string LastBlockId);

    private sealed record CheckpointSandwich(
        int LowerHeight,
        string LowerBlockId,
        int UpperHeight,
        string UpperBlockId,
        int UpperSourceHop,
        int UpperSourceRecordIndex,
        int RecordIndexBase);

    private sealed record PathHop(
        int Hop,
        string LocatorBlockId,
        string PayloadSha256,
        string LastBlockId);

    private sealed record ValidationScope(
        bool CanonicalCount,
        bool RecordFraming,
        bool Anchor,
        bool InternalLinkage,
        bool ClaimedTargetProofOfWork,
        bool IndependentFullBatchEquality,
        bool CheckpointSandwich,
        bool DifficultyAdjustmentAlgorithm);
}
