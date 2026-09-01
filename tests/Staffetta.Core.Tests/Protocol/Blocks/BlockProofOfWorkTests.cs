using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Tests.Protocol.Blocks;

[TestClass]
public sealed class BlockProofOfWorkTests
{
    private const string FixtureFileName = "headers-mainnet-after-genesis-2000-20260830.bin";

    private static readonly UInt256 MainnetProofOfWorkLimit = CompactTarget.Decode(0x1d00ffff).Value;

    [TestMethod]
    public void HashAtTargetPassesAndHashAboveTargetFails()
    {
        var target = HashFromDisplayHex(
            "00000000ffff0000000000000000000000000000000000000000000000000000");
        var aboveTarget = HashFromDisplayHex(
            "00000000ffff0000000000000000000000000000000000000000000000000001");

        Assert.AreEqual(
            BlockProofOfWorkValidation.Valid,
            BlockProofOfWork.Validate(target, 0x1d00ffff, MainnetProofOfWorkLimit));
        Assert.AreEqual(
            BlockProofOfWorkValidation.HashAboveTarget,
            BlockProofOfWork.Validate(aboveTarget, 0x1d00ffff, MainnetProofOfWorkLimit));
    }

    [TestMethod]
    public void ValidationRejectsEveryInvalidTargetClass()
    {
        var zeroHash = default(Hash256);

        Assert.AreEqual(
            BlockProofOfWorkValidation.NegativeTarget,
            BlockProofOfWork.Validate(zeroHash, 0x1d80ffff, MainnetProofOfWorkLimit));
        Assert.AreEqual(
            BlockProofOfWorkValidation.ZeroTarget,
            BlockProofOfWork.Validate(zeroHash, 0, MainnetProofOfWorkLimit));
        Assert.AreEqual(
            BlockProofOfWorkValidation.TargetOverflow,
            BlockProofOfWork.Validate(zeroHash, 0x21123456, MainnetProofOfWorkLimit));
        Assert.AreEqual(
            BlockProofOfWorkValidation.TargetAboveLimit,
            BlockProofOfWork.Validate(zeroHash, 0x1d010000, MainnetProofOfWorkLimit));
    }

    [TestMethod]
    public void ValidationAcceptsAValidNonCanonicalCompactEncoding()
    {
        var atTarget = HashFromDisplayHex(
            "0000000000000000000000000000000000000000000000000000000000000012");
        var aboveTarget = HashFromDisplayHex(
            "0000000000000000000000000000000000000000000000000000000000000013");

        Assert.AreEqual(
            BlockProofOfWorkValidation.Valid,
            BlockProofOfWork.Validate(atTarget, 0x01123456, MainnetProofOfWorkLimit));
        Assert.AreEqual(
            BlockProofOfWorkValidation.HashAboveTarget,
            BlockProofOfWork.Validate(aboveTarget, 0x01123456, MainnetProofOfWorkLimit));
    }

    [TestMethod]
    public void BlockWorkMatchesExactNodeConstants()
    {
        Assert.AreEqual(UInt256.FromUInt64(0x100010001), BlockProofOfWork.GetBlockWork(0x1d00ffff));
        Assert.AreEqual(UInt256.FromUInt64(2), BlockProofOfWork.GetBlockWork(0x207fffff));
        Assert.AreEqual(UInt256.FromUInt64(14), BlockProofOfWork.GetBlockWork(0x20123456));
    }

    [TestMethod]
    public void InvalidTargetsHaveZeroBlockWorkWithoutApplyingANetworkLimit()
    {
        Assert.AreEqual(UInt256.Zero, BlockProofOfWork.GetBlockWork(0));
        Assert.AreEqual(UInt256.Zero, BlockProofOfWork.GetBlockWork(0x1d80ffff));
        Assert.AreEqual(UInt256.Zero, BlockProofOfWork.GetBlockWork(0x21123456));
        Assert.AreNotEqual(UInt256.Zero, BlockProofOfWork.GetBlockWork(0x1d010000));
    }

    [TestMethod]
    public void AllCapturedMainnetHeadersSatisfyTheirClaimedProofOfWork()
    {
        var payload = File.ReadAllBytes(GetFixturePath(FixtureFileName));
        var headers = new BlockHeader[HeadersPayloadCodec.MaximumHeaderCount];

        Assert.AreEqual(
            OperationStatus.Done,
            HeadersPayloadCodec.TryParse(payload, headers, out var count));
        Assert.AreEqual(HeadersPayloadCodec.MaximumHeaderCount, count);

        for (var index = 0; index < count; index++)
        {
            Assert.AreEqual(
                BlockProofOfWorkValidation.Valid,
                BlockProofOfWork.Validate(headers[index], MainnetProofOfWorkLimit),
                $"Header {index + 1} failed proof-of-work validation.");
        }
    }

    private static Hash256 HashFromDisplayHex(string displayHex)
    {
        var wireBytes = Convert.FromHexString(displayHex);
        Array.Reverse(wireBytes);
        Assert.AreEqual(OperationStatus.Done, Hash256.TryCreate(wireBytes, out var hash));
        return hash;
    }

    private static string GetFixturePath(string fileName) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "Bsv", fileName);
}
