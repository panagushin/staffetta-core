using System.Buffers;
using Staffetta.Core.Protocol.Encoding;
using Staffetta.Core.Protocol.Transactions;

namespace Staffetta.Core.Protocol.Blocks;

/// <summary>Streams a legacy BSV block using fixed header scratch and a logarithmic Merkle frontier.</summary>
/// <remarks>
/// Single-consumer. Counts never preallocate storage. Transaction commit callbacks are provisional
/// within this enclosing block; publish only after Commit succeeds following wire validation.
/// Checks canonical serialization, transaction monetary ranges, Merkle root and visible tree mutation.
/// It does not execute scripts, validate coinbase/subsidy, or establish header-chain membership.
/// </remarks>
public sealed class LegacyBlockParser : IDisposable
{
    private readonly IBlockSink sink;
    private readonly ITransactionPayloadSink? payloadSink;
    private readonly BsvTransactionMonetaryRangeValidator monetary;
    private readonly LegacyTransactionParser transaction;
    private readonly StreamingMerkleTree tree;
    private readonly byte[] headerBytes = new byte[80];
    private IncrementalCompactSizeReader countReader;
    private BlockHeader header;
    private int headerLength;
    private ulong transactionCount;
    private ulong transactionIndex;
    private ulong length;
    private bool started;
    private bool transactionStarted;
    private bool faulted;
    private bool busy;
    private bool disposed;

    /// <summary>Creates a parser with provisional structure, transaction and optional borrowed raw-payload consumers.</summary>
    public LegacyBlockParser(IBlockSink sink, ILegacyTransactionSink transactionSink, ITransactionPayloadSink? payloadSink = null)
    {
        this.sink = sink ?? throw new ArgumentNullException(nameof(sink));
        this.payloadSink = payloadSink;
        monetary = new BsvTransactionMonetaryRangeValidator(transactionSink);
        transaction = new LegacyTransactionParser(monetary);
        tree = new StreamingMerkleTree(sink);
    }

    /// <summary>Consumes at most one block, leaving trailing bytes untouched; no effects are published by this method.</summary>
    /// <returns>Done when all declared transactions have parsed, NeedMoreData while incomplete, or InvalidData on terminal rejection.</returns>
    public OperationStatus Consume(ReadOnlySpan<byte> source, out int bytesConsumed)
    {
        Enter();
        bytesConsumed = 0;
        try
        {
            if (faulted) { return OperationStatus.InvalidData; }
            if (headerLength < 80)
            {
                var take = Math.Min(80 - headerLength, source.Length);
                source[..take].CopyTo(headerBytes.AsSpan(headerLength));
                headerLength += take; bytesConsumed += take; length += (ulong)take;
                if (headerLength < 80) { return OperationStatus.NeedMoreData; }
                _ = BlockHeaderCodec.TryParse(headerBytes, out header, out _);
            }
            if (!started)
            {
                var take = countReader.Consume(source[bytesConsumed..]);
                bytesConsumed += take; length = checked(length + (ulong)take);
                if (!countReader.IsComplete) { return OperationStatus.NeedMoreData; }
                if (!countReader.IsCanonical || countReader.Value == 0) { return Reject(); }
                transactionCount = countReader.Value;
                started = true;
                sink.OnBlockStarted(header, transactionCount);
                CheckCallback();
            }
            while (transactionIndex < transactionCount && bytesConsumed < source.Length)
            {
                if (!transactionStarted)
                {
                    transactionStarted = true;
                    sink.OnTransactionStarted(transactionIndex);
                    CheckCallback();
                }
                var status = transaction.Consume(source[bytesConsumed..], out var take);
                payloadSink?.OnTransactionPayload(source.Slice(bytesConsumed, take));
                bytesConsumed += take; length = checked(length + (ulong)take);
                CheckCallback();
                if (status == OperationStatus.InvalidData) { return Reject(); }
                if (status == OperationStatus.NeedMoreData) { return status; }
                if (transaction.Commit(out var summary) != OperationStatus.Done ||
                    !monetary.TryGetCommittedValidation(out var validation) || !validation.IsValid) { return Reject(); }
                CheckCallback();
                tree.Add(summary.TransactionId);
                CheckCallback();
                transactionIndex++;
                transactionStarted = false;
            }
            return transactionIndex == transactionCount ? OperationStatus.Done : OperationStatus.NeedMoreData;
        }
        catch (OverflowException) { return Reject(); }
        catch { faulted = true; throw; }
        finally { busy = false; }
    }

    /// <summary>Checks the full Merkle root and publishes only after the caller has validated enclosing framing and exact length.</summary>
    /// <returns>Done on successful publication/reset, otherwise terminal InvalidData.</returns>
    public OperationStatus Commit(out LegacyBlockSummary summary)
    {
        Enter();
        summary = default;
        try
        {
            if (faulted || !started || transactionIndex != transactionCount) { return Reject(); }
            var root = tree.Finish();
            CheckCallback();
            if (tree.Mutated || root != header.MerkleRoot) { return Reject(); }
            summary = new(header, header.ComputeHash(), transactionCount, length);
            sink.OnBlockCommitted(summary);
            CheckCallback();
            headerLength = 0; countReader = default; transactionCount = transactionIndex = length = 0;
            started = transactionStarted = false; tree.Reset();
            return OperationStatus.Done;
        }
        catch { faulted = true; throw; }
        finally { busy = false; }
    }

    /// <summary>Terminally discards a block on truncation, checksum failure, or caller rejection.</summary>
    public void Abort()
    {
        Enter();
        try { _ = Reject(); }
        finally { busy = false; }
    }

    /// <summary>Releases transaction hashing resources without publishing or notifying callbacks.</summary>
    public void Dispose()
    {
        if (disposed) { return; }
        Enter();
        try { disposed = true; transaction.Dispose(); }
        finally { busy = false; }
    }

    private OperationStatus Reject()
    {
        faulted = true;
        if (started)
        {
            started = false;
            if (!transaction.IsFaulted) { transaction.Abort(); }
            sink.OnBlockAborted();
        }
        return OperationStatus.InvalidData;
    }

    private void Enter()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (busy) { faulted = true; throw new InvalidOperationException("Block callbacks cannot re-enter their parser."); }
        busy = true;
    }
    private void CheckCallback()
    {
        if (faulted) { throw new InvalidOperationException("A block callback faulted its owner."); }
    }
}
