using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

internal readonly record struct BlockDifficultyContext(
    int Height,
    uint Timestamp,
    UInt256 CumulativeChainWork);
