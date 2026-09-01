using System.Numerics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Tests.Protocol.Cryptography;

[TestClass]
public sealed class UInt256Tests
{
    [TestMethod]
    public void ShiftsAreBoundedToTwoHundredFiftySixBits()
    {
        var one = UInt256.FromUInt64(1);
        var highestBit = one.ShiftLeft(255);

        Assert.AreEqual(256, highestBit.BitLength);
        Assert.AreEqual(one, highestBit.ShiftRight(255));
        Assert.AreEqual(UInt256.Zero, highestBit.ShiftLeft(1));
        Assert.AreEqual(UInt256.Zero, one.ShiftLeft(256));
        Assert.AreEqual(UInt256.Zero, highestBit.ShiftRight(256));
    }

    [TestMethod]
    public void DivisionHandlesAHighBitRemainderWithoutEscapingUInt256()
    {
        var highestBit = UInt256.FromUInt64(1).ShiftLeft(255);

        Assert.AreEqual(UInt256.FromUInt64(1), UInt256.Divide(UInt256.MaxValue, highestBit));
        Assert.AreEqual(UInt256.MaxValue.ShiftRight(1), UInt256.Divide(UInt256.MaxValue, UInt256.FromUInt64(2)));
    }

    [TestMethod]
    public void AddOneWrapsAtTheUInt256Boundary()
    {
        Assert.AreEqual(UInt256.Zero, UInt256.MaxValue.AddOne());
    }

    [TestMethod]
    public void DivisionMatchesUnsignedBigIntegerAcrossBoundedInputs()
    {
        var random = new Random(0x5aff_e77a);
        for (var index = 0; index < 128; index++)
        {
            var numeratorBytes = new byte[32];
            var denominatorBytes = new byte[32];
            random.NextBytes(numeratorBytes);
            random.NextBytes(denominatorBytes);
            denominatorBytes[0] |= 1;

            var expected = new BigInteger(numeratorBytes, isUnsigned: true, isBigEndian: false) /
                new BigInteger(denominatorBytes, isUnsigned: true, isBigEndian: false);

            Assert.AreEqual(
                FromBigInteger(expected),
                UInt256.Divide(
                    UInt256.FromLittleEndian(numeratorBytes),
                    UInt256.FromLittleEndian(denominatorBytes)),
                $"Division case {index} diverged.");
        }
    }

    private static UInt256 FromBigInteger(BigInteger value)
    {
        Span<byte> bytes = stackalloc byte[32];
        bytes.Clear();
        Assert.IsTrue(value.TryWriteBytes(bytes, out _, isUnsigned: true, isBigEndian: false));
        return UInt256.FromLittleEndian(bytes);
    }
}
