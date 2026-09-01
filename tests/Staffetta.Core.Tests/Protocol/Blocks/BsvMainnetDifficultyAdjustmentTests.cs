using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Tests.Protocol.Blocks;

[TestClass]
public sealed class BsvMainnetDifficultyAdjustmentTests
{
    [DataTestMethod]
    [DataRow(10u, 20u, 30u)]
    [DataRow(10u, 30u, 20u)]
    [DataRow(20u, 10u, 30u)]
    [DataRow(20u, 30u, 10u)]
    [DataRow(30u, 10u, 20u)]
    [DataRow(30u, 20u, 10u)]
    public void SuitableBlockSelectsTheTimestampMedianForEveryPermutation(
        uint firstTimestamp,
        uint secondTimestamp,
        uint thirdTimestamp)
    {
        BlockDifficultyContext[] candidates =
        [
            Entry(1, firstTimestamp, 1),
            Entry(2, secondTimestamp, 2),
            Entry(3, thirdTimestamp, 3),
        ];

        Assert.AreEqual(
            20u,
            BsvMainnetDifficultyAdjustment.SelectSuitableBlock(candidates).Timestamp);
    }

    [TestMethod]
    public void SuitableBlockUsesStrictComparisonsAndPreservesTieIdentity()
    {
        BlockDifficultyContext[] candidates =
        [
            Entry(1, 10, 1),
            Entry(2, 20, 2),
            Entry(3, 10, 3),
        ];

        BlockDifficultyContext selected =
            BsvMainnetDifficultyAdjustment.SelectSuitableBlock(candidates);

        Assert.AreEqual(3, selected.Height);
        Assert.AreEqual(10u, selected.Timestamp);
    }

    [TestMethod]
    public void CalculationAppliesTheMinimumTimespanClamp()
    {
        BlockDifficultyContext[] context = CreateContext(
            BsvMainnetDifficultyAdjustment.ActivationPreviousHeight,
            secondsPerBlock: 1,
            workIncrement: 1_000_000);

        var status = BsvMainnetDifficultyAdjustment.CalculateNextBits(
            context,
            UInt256.MaxValue,
            out uint compactTarget);

        Assert.AreEqual(DifficultyAdjustmentCalculationStatus.Done, status);
        Assert.AreEqual<uint>(0x1e08637b, compactTarget);
    }

    [TestMethod]
    public void CalculationAppliesTheMaximumTimespanClamp()
    {
        BlockDifficultyContext[] context = CreateContext(
            BsvMainnetDifficultyAdjustment.ActivationPreviousHeight,
            secondsPerBlock: 10_000,
            workIncrement: 1_000_000);

        var status = BsvMainnetDifficultyAdjustment.CalculateNextBits(
            context,
            UInt256.MaxValue,
            out uint compactTarget);

        Assert.AreEqual(DifficultyAdjustmentCalculationStatus.Done, status);
        Assert.AreEqual<uint>(0x1e218def, compactTarget);
    }

    [TestMethod]
    public void CalculationCapsTheResultAtTheProofOfWorkLimit()
    {
        BlockDifficultyContext[] context = CreateContext(
            BsvMainnetDifficultyAdjustment.ActivationPreviousHeight,
            secondsPerBlock: 10_000,
            workIncrement: 1_000);
        UInt256 mainnetLimit = CompactTarget.Decode(0x1d00ffff).Value;

        var status = BsvMainnetDifficultyAdjustment.CalculateNextBits(
            context,
            mainnetLimit,
            out uint compactTarget);

        Assert.AreEqual(DifficultyAdjustmentCalculationStatus.Done, status);
        Assert.AreEqual<uint>(0x1d00ffff, compactTarget);
    }

    [TestMethod]
    public void ActivationUsesThePreviousBlockHeightBoundary()
    {
        BlockDifficultyContext[] inactive = CreateContext(
            BsvMainnetDifficultyAdjustment.ActivationPreviousHeight - 1,
            secondsPerBlock: 600,
            workIncrement: 1_000_000);
        BlockDifficultyContext[] active = CreateContext(
            BsvMainnetDifficultyAdjustment.ActivationPreviousHeight,
            secondsPerBlock: 600,
            workIncrement: 1_000_000);

        Assert.AreEqual(
            DifficultyAdjustmentCalculationStatus.Inactive,
            BsvMainnetDifficultyAdjustment.CalculateNextBits(inactive, UInt256.MaxValue, out _));
        Assert.AreEqual(
            DifficultyAdjustmentCalculationStatus.Done,
            BsvMainnetDifficultyAdjustment.CalculateNextBits(active, UInt256.MaxValue, out _));
    }

    [TestMethod]
    public void CalculationRejectsMissingOrNonAuthoritativeContext()
    {
        BlockDifficultyContext[] valid = CreateContext(
            BsvMainnetDifficultyAdjustment.ActivationPreviousHeight,
            secondsPerBlock: 600,
            workIncrement: 1_000_000);
        var heightGap = (BlockDifficultyContext[])valid.Clone();
        heightGap[73] = heightGap[73] with { Height = heightGap[73].Height + 1 };
        var repeatedWork = (BlockDifficultyContext[])valid.Clone();
        repeatedWork[73] = repeatedWork[73] with
        {
            CumulativeChainWork = repeatedWork[72].CumulativeChainWork,
        };

        Assert.AreEqual(
            DifficultyAdjustmentCalculationStatus.InvalidContextLength,
            BsvMainnetDifficultyAdjustment.CalculateNextBits(valid.AsSpan(1), UInt256.MaxValue, out _));
        Assert.AreEqual(
            DifficultyAdjustmentCalculationStatus.NonConsecutiveHeights,
            BsvMainnetDifficultyAdjustment.CalculateNextBits(heightGap, UInt256.MaxValue, out _));
        Assert.AreEqual(
            DifficultyAdjustmentCalculationStatus.NonIncreasingChainWork,
            BsvMainnetDifficultyAdjustment.CalculateNextBits(repeatedWork, UInt256.MaxValue, out _));
    }

    [TestMethod]
    public void CalculationRejectsAWindowWhoseIntegerWorkRateIsZero()
    {
        BlockDifficultyContext[] context = CreateContext(
            BsvMainnetDifficultyAdjustment.ActivationPreviousHeight,
            secondsPerBlock: 10_000,
            workIncrement: 1);

        Assert.AreEqual(
            DifficultyAdjustmentCalculationStatus.ZeroComputedWork,
            BsvMainnetDifficultyAdjustment.CalculateNextBits(context, UInt256.MaxValue, out _));
    }

    [TestMethod]
    public void RequiredArithmeticWrapsAtTheUInt256Boundary()
    {
        UInt256 one = UInt256.FromUInt64(1);

        Assert.AreEqual(UInt256.Zero, UInt256.MaxValue.Add(one));
        Assert.AreEqual(UInt256.MaxValue, UInt256.Zero.Subtract(one));
        Assert.AreEqual(
            UInt256.Zero.Subtract(UInt256.FromUInt64(600)),
            UInt256.MaxValue.Multiply(600));
    }

    private static BlockDifficultyContext[] CreateContext(
        int previousHeight,
        uint secondsPerBlock,
        ulong workIncrement)
    {
        var context = new BlockDifficultyContext[BsvMainnetDifficultyAdjustment.RequiredContextLength];
        UInt256 cumulativeWork = UInt256.Zero;
        UInt256 increment = UInt256.FromUInt64(workIncrement);
        int firstHeight = previousHeight - context.Length + 1;
        for (var index = 0; index < context.Length; index++)
        {
            cumulativeWork = cumulativeWork.Add(increment);
            context[index] = new BlockDifficultyContext(
                firstHeight + index,
                checked(1_000_000u + ((uint)index * secondsPerBlock)),
                cumulativeWork);
        }

        return context;
    }

    private static BlockDifficultyContext Entry(int height, uint timestamp, ulong work) =>
        new(height, timestamp, UInt256.FromUInt64(work));
}
