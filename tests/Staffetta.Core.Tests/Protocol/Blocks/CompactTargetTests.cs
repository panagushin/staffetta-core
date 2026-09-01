using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Tests.Protocol.Blocks;

[TestClass]
public sealed class CompactTargetTests
{
    [TestMethod]
    public void DecodeAcceptsNonCanonicalCompactAndEncodeNormalizesIt()
    {
        var target = CompactTarget.Decode(0x01123456);

        Assert.AreEqual(UInt256.FromUInt64(0x12), target.Value);
        Assert.IsFalse(target.IsNegative);
        Assert.IsFalse(target.IsOverflow);
        Assert.AreEqual<uint>(0x01120000, CompactTarget.Encode(target.Value));
    }

    [TestMethod]
    public void DecodeReportsSignAndOverflowIndependentlyFromTheMagnitude()
    {
        var negative = CompactTarget.Decode(0x01923456);
        var overflow = CompactTarget.Decode(0x21123456);

        Assert.AreEqual(UInt256.FromUInt64(0x12), negative.Value);
        Assert.IsTrue(negative.IsNegative);
        Assert.IsFalse(negative.IsOverflow);
        Assert.IsFalse(overflow.IsNegative);
        Assert.IsTrue(overflow.IsOverflow);
    }

    [TestMethod]
    public void DecodeTruncatesSmallExponentsBeforeClassifyingZeroAndSign()
    {
        var target = CompactTarget.Decode(0x01803456);

        Assert.AreEqual(UInt256.Zero, target.Value);
        Assert.IsFalse(target.IsNegative);
        Assert.IsFalse(target.IsOverflow);
        Assert.AreEqual<uint>(0, CompactTarget.Encode(target.Value));
    }

    [TestMethod]
    public void EncodeReservesTheMantissaSignBit()
    {
        Assert.AreEqual<uint>(0x02008000, CompactTarget.Encode(UInt256.FromUInt64(0x80)));
        Assert.AreEqual<uint>(0x1d00ffff, CompactTarget.Encode(CompactTarget.Decode(0x1d00ffff).Value));
    }

    [TestMethod]
    public void EncodeAppliesRequestedSignOnlyToNonZeroValues()
    {
        Assert.AreEqual<uint>(0, CompactTarget.Encode(UInt256.Zero, isNegative: true));
        Assert.AreEqual<uint>(0x01920000, CompactTarget.Encode(UInt256.FromUInt64(0x12), isNegative: true));
    }
}
