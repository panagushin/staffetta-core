using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

internal enum DifficultyAdjustmentCalculationStatus
{
    Done,
    Inactive,
    InvalidContextLength,
    NonConsecutiveHeights,
    NonIncreasingChainWork,
    ZeroComputedWork,
}

internal static class BsvMainnetDifficultyAdjustment
{
    internal const int ActivationPreviousHeight = 504_031;
    internal const int RequiredContextLength = 147;
    internal const int MinimumTimespan = 43_200;
    internal const int MaximumTimespan = 172_800;

    private const uint TargetSpacing = 600;

    internal static DifficultyAdjustmentCalculationStatus CalculateNextBits(
        ReadOnlySpan<BlockDifficultyContext> context,
        UInt256 proofOfWorkLimit,
        out uint compactTarget)
    {
        compactTarget = 0;
        if (context.Length != RequiredContextLength)
        {
            return DifficultyAdjustmentCalculationStatus.InvalidContextLength;
        }

        for (var index = 1; index < context.Length; index++)
        {
            if (context[index].Height != context[index - 1].Height + 1)
            {
                return DifficultyAdjustmentCalculationStatus.NonConsecutiveHeights;
            }

            if (context[index].CumulativeChainWork <= context[index - 1].CumulativeChainWork)
            {
                return DifficultyAdjustmentCalculationStatus.NonIncreasingChainWork;
            }
        }

        if (context[^1].Height < ActivationPreviousHeight)
        {
            return DifficultyAdjustmentCalculationStatus.Inactive;
        }

        BlockDifficultyContext first = SelectSuitableBlock(context[..3]);
        BlockDifficultyContext last = SelectSuitableBlock(context[^3..]);
        UInt256 work = last.CumulativeChainWork
            .Subtract(first.CumulativeChainWork)
            .Multiply(TargetSpacing);

        long actualTimespan = (long)last.Timestamp - first.Timestamp;
        actualTimespan = Math.Clamp(actualTimespan, MinimumTimespan, MaximumTimespan);
        work = UInt256.Divide(work, UInt256.FromUInt64((ulong)actualTimespan));
        if (work.IsZero)
        {
            return DifficultyAdjustmentCalculationStatus.ZeroComputedWork;
        }

        UInt256 target = UInt256.Divide(work.Negate(), work);
        if (target > proofOfWorkLimit)
        {
            target = proofOfWorkLimit;
        }

        compactTarget = CompactTarget.Encode(target);
        return DifficultyAdjustmentCalculationStatus.Done;
    }

    internal static BlockDifficultyContext SelectSuitableBlock(
        ReadOnlySpan<BlockDifficultyContext> candidates)
    {
        if (candidates.Length != 3)
        {
            throw new ArgumentException("Suitable-block selection requires exactly three entries.", nameof(candidates));
        }

        BlockDifficultyContext first = candidates[0];
        BlockDifficultyContext middle = candidates[1];
        BlockDifficultyContext last = candidates[2];

        if (first.Timestamp > last.Timestamp)
        {
            (first, last) = (last, first);
        }

        if (first.Timestamp > middle.Timestamp)
        {
            (first, middle) = (middle, first);
        }

        if (middle.Timestamp > last.Timestamp)
        {
            (middle, last) = (last, middle);
        }

        return middle;
    }
}
