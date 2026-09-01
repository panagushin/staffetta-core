using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

internal enum BlockProofOfWorkValidation
{
    Valid,
    NegativeTarget,
    ZeroTarget,
    TargetOverflow,
    TargetAboveLimit,
    HashAboveTarget,
}

internal static class BlockProofOfWork
{
    internal static BlockProofOfWorkValidation Validate(in BlockHeader header, UInt256 proofOfWorkLimit) =>
        Validate(header.ComputeHash(), header.Bits, proofOfWorkLimit);

    internal static BlockProofOfWorkValidation Validate(
        Hash256 hash,
        uint compactTarget,
        UInt256 proofOfWorkLimit)
    {
        var target = CompactTarget.Decode(compactTarget);
        if (target.IsNegative)
        {
            return BlockProofOfWorkValidation.NegativeTarget;
        }

        if (target.Value.IsZero)
        {
            return BlockProofOfWorkValidation.ZeroTarget;
        }

        if (target.IsOverflow)
        {
            return BlockProofOfWorkValidation.TargetOverflow;
        }

        if (target.Value > proofOfWorkLimit)
        {
            return BlockProofOfWorkValidation.TargetAboveLimit;
        }

        return hash.ToUInt256() > target.Value
            ? BlockProofOfWorkValidation.HashAboveTarget
            : BlockProofOfWorkValidation.Valid;
    }

    internal static UInt256 GetBlockWork(uint compactTarget)
    {
        var target = CompactTarget.Decode(compactTarget);
        if (target.IsNegative || target.IsOverflow || target.Value.IsZero)
        {
            return UInt256.Zero;
        }

        var denominator = target.Value.AddOne();
        return UInt256.Divide(target.Value.OnesComplement(), denominator).AddOne();
    }
}
