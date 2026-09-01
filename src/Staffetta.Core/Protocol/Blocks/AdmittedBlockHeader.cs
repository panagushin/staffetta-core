using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

internal readonly record struct AdmittedBlockHeader(
    BlockHeader Header,
    Hash256 Hash,
    int Height,
    UInt256 CumulativeChainWork);
