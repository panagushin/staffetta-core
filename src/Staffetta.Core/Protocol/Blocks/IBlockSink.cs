using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

/// <summary>Receives provisional block structure and Merkle nodes without retaining block bodies.</summary>
/// <remarks>Transaction callbacks and nodes remain provisional until OnBlockCommitted. Callbacks must not re-enter the parser or session. Exceptional teardown may omit OnBlockAborted.</remarks>
public interface IBlockSink
{
    /// <summary>Starts one provisional block with a canonical, nonzero transaction count.</summary>
    void OnBlockStarted(in BlockHeader header, ulong transactionCount);
    /// <summary>Starts the zero-based transaction before its first payload chunk or field callback.</summary>
    void OnTransactionStarted(ulong transactionIndex);
    /// <summary>Receives one tree node; level zero contains transaction identifiers. Missing odd siblings are implicit duplicates.</summary>
    void OnMerkleNode(int level, ulong index, Hash256 hash);
    /// <summary>Publishes a structurally complete block after Merkle-root and enclosing-frame validation.</summary>
    void OnBlockCommitted(in LegacyBlockSummary summary);
    /// <summary>Discards provisional block effects; this callback is not guaranteed after callback exceptions.</summary>
    void OnBlockAborted();
}

/// <summary>A parsed block identity and size, without script, UTXO, or selected-chain validity claims.</summary>
/// <param name="Header">The parsed block header.</param>
/// <param name="BlockHash">The double-SHA256 header identifier.</param>
/// <param name="TransactionCount">The number of parsed transactions.</param>
/// <param name="SerializedLength">The payload byte count, excluding wire framing.</param>
public readonly record struct LegacyBlockSummary(BlockHeader Header, Hash256 BlockHash, ulong TransactionCount, ulong SerializedLength);
