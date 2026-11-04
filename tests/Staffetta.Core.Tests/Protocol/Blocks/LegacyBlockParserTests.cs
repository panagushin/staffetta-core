using System.Buffers;
using System.Buffers.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Transactions;

namespace Staffetta.Core.Tests.Protocol.Blocks;

[TestClass]
public sealed class LegacyBlockParserTests
{
    [TestMethod]
    public void EverySplitPreservesTransactionBytesIndicesAndFullTree()
    {
        var payload = Block(5);
        for (var split = 0; split <= payload.Length; split++)
        {
            var sink = new Sink();
            using var parser = new LegacyBlockParser(sink, sink, sink);
            _ = parser.Consume(payload.AsSpan(0, split), out var first);
            Assert.AreEqual(split, first);
            Assert.AreEqual(OperationStatus.Done, parser.Consume(payload.AsSpan(split), out var last));
            Assert.AreEqual(payload.Length - split, last);
            Assert.AreEqual(0, sink.BlockCommits);
            Assert.AreEqual(OperationStatus.Done, parser.Commit(out var summary));
            Assert.AreEqual((ulong)5, summary.TransactionCount);
            Assert.AreEqual((ulong)payload.Length, summary.SerializedLength);
            CollectionAssert.AreEqual(payload[81..], sink.Raw.ToArray());
            CollectionAssert.AreEqual(new ulong[] { 0, 1, 2, 3, 4 }, sink.Indices.ToArray());
            Assert.AreEqual(summary.Header.MerkleRoot, sink.Nodes[(3, 0)]);
            Assert.AreEqual(1, sink.BlockCommits);
        }
    }

    [TestMethod]
    public void OddAndPowerOfTwoTreesMatchIndependentMaterializedConstruction()
    {
        for (var count = 1; count <= 65; count++)
        {
            var sink = new Sink();
            using var parser = new LegacyBlockParser(sink, sink);
            var block = Block(count);
            Assert.AreEqual(OperationStatus.Done, parser.Consume(block, out _));
            Assert.AreEqual(OperationStatus.Done, parser.Commit(out _));
        }
    }

    [TestMethod]
    public void WrongRootTruncationMutationAndNoncanonicalCountNeverCommit()
    {
        foreach (var mode in new[] { "root", "truncated", "duplicate", "count" })
        {
            var block = Block(2, duplicate: mode == "duplicate");
            if (mode == "root") { block[36] ^= 1; }
            if (mode == "truncated") { block = block[..^1]; }
            if (mode == "count") { block = [.. block[..80], 0xfd, 2, 0, .. block[81..]]; }
            var sink = new Sink();
            using var parser = new LegacyBlockParser(sink, sink);
            _ = parser.Consume(block, out _);
            Assert.AreEqual(OperationStatus.InvalidData, parser.Commit(out _));
            Assert.AreEqual(0, sink.BlockCommits);
        }
    }

    [TestMethod]
    public void LiveRecapturedBlockVerifiesThroughOneByteChunks()
    {
        var block = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures/Bsv/block-mainnet-504032-20261105.bin"));
        var sink = new Sink();
        using var parser = new LegacyBlockParser(sink, sink);
        for (var offset = 0; offset < block.Length; offset++)
        {
            Assert.AreEqual(offset == block.Length - 1 ? OperationStatus.Done : OperationStatus.NeedMoreData,
                parser.Consume(block.AsSpan(offset, 1), out var used));
            Assert.AreEqual(1, used);
        }
        Assert.AreEqual(OperationStatus.Done, parser.Commit(out var summary));
        Assert.AreEqual(Hash256.FromWireBytes(Convert.FromHexString("00000000000000000343e9875012f2062554c8752929892c82a0c0743ac7dcfd").Reverse().ToArray()), summary.BlockHash);
    }

    [TestMethod]
    public void SwallowedBlockCallbackReentryCannotPublish()
    {
        var sink = new Sink();
        using var parser = new LegacyBlockParser(sink, sink);
        sink.Callback = () => { try { _ = parser.Consume([], out _); } catch (InvalidOperationException) { } };
        Assert.ThrowsException<InvalidOperationException>(() => parser.Consume(Block(1), out _));
        Assert.AreEqual(0, sink.BlockCommits);
    }

    [TestMethod]
    [TestCategory("AllocationEvidence")]
    public void LargeOpaqueBlockPayloadAndUntrustedCountsHaveBoundedParserAllocation()
    {
        var small = Block(1, opaque: 1024 * 1024);
        var large = Block(1, opaque: 16 * 1024 * 1024);
        _ = Allocated(small);
        var first = Allocated(small);
        var second = Allocated(large);
        Assert.IsTrue(second <= first + 8192, $"Allocation grew from {first} to {second}.");
        var sink = new Sink(collect: false);
        using var parser = new LegacyBlockParser(sink, sink);
        var declared = new byte[89]; declared[80] = 0xff; declared.AsSpan(81).Fill(0xff);
        Assert.AreEqual(OperationStatus.NeedMoreData, parser.Consume(declared, out _));
    }

    private static long Allocated(byte[] block)
    {
        var sink = new Sink(collect: false);
        var start = GC.GetAllocatedBytesForCurrentThread();
        using var parser = new LegacyBlockParser(sink, sink);
        for (var offset = 0; offset < block.Length; offset += 4096)
        {
            _ = parser.Consume(block.AsSpan(offset, Math.Min(4096, block.Length - offset)), out _);
        }
        Assert.AreEqual(OperationStatus.Done, parser.Commit(out _));
        return GC.GetAllocatedBytesForCurrentThread() - start;
    }

    internal static byte[] Block(int count, bool duplicate = false, int opaque = 0)
    {
        var transactions = Enumerable.Range(0, count).Select(i => Transaction(duplicate ? 1 : i + 1, opaque)).ToArray();
        var nodes = transactions.Select(tx => Hash256.DoubleSha256(tx)).ToList();
        while (nodes.Count > 1)
        {
            var next = new List<Hash256>();
            for (var i = 0; i < nodes.Count; i += 2)
            {
                var pair = new byte[64]; nodes[i].TryCopyWireBytesTo(pair, out _);
                nodes[Math.Min(i + 1, nodes.Count - 1)].TryCopyWireBytesTo(pair.AsSpan(32), out _);
                next.Add(Hash256.DoubleSha256(pair));
            }
            nodes = next;
        }
        using var output = new MemoryStream();
        var header = new byte[80]; nodes[0].TryCopyWireBytesTo(header.AsSpan(36), out _);
        output.Write(header); output.WriteByte((byte)count);
        foreach (var tx in transactions) { output.Write(tx); }
        return output.ToArray();
    }

    private static byte[] Transaction(int seed, int opaque)
    {
        using var output = new MemoryStream(); using var writer = new BinaryWriter(output);
        writer.Write(1); writer.Write((byte)1);
        var prev = new byte[32]; BinaryPrimitives.WriteInt32LittleEndian(prev, seed);
        writer.Write(prev); writer.Write(0U); writer.Write((byte)0); writer.Write(uint.MaxValue);
        writer.Write((byte)1); writer.Write(1L);
        if (opaque == 0) { writer.Write((byte)0); }
        else { writer.Write((byte)0xfe); writer.Write((uint)opaque); writer.Write(new byte[opaque]); }
        writer.Write(0U); return output.ToArray();
    }

    private sealed class Sink(bool collect = true) : IBlockSink, ILegacyTransactionSink, ITransactionPayloadSink
    {
        internal int BlockCommits;
        internal Action? Callback;
        internal List<ulong> Indices { get; } = [];
        internal Dictionary<(int, ulong), Hash256> Nodes { get; } = [];
        internal MemoryStream Raw { get; } = new();
        public void OnBlockStarted(in BlockHeader header, ulong count) { Callback?.Invoke(); }
        public void OnTransactionStarted(ulong index) { if (collect) { Indices.Add(index); } }
        public void OnMerkleNode(int level, ulong index, Hash256 hash) { if (collect) { Nodes[(level, index)] = hash; } }
        public void OnBlockCommitted(in LegacyBlockSummary summary) => BlockCommits++;
        public void OnBlockAborted() { }
        public void OnTransactionPayload(ReadOnlySpan<byte> bytes) { if (collect) { Raw.Write(bytes); } }
        public void OnTransactionStarted(int version, ulong inputs) { }
        public void OnInputStarted(ulong index, in OutPoint previous, ulong length) { }
        public void OnInputScriptChunk(ulong index, ReadOnlySpan<byte> bytes) { }
        public void OnInputCompleted(ulong index, uint sequence) { }
        public void OnOutputsStarted(ulong count) { }
        public void OnOutputStarted(ulong index, long value, ulong length) { }
        public void OnOutputScriptChunk(ulong index, ReadOnlySpan<byte> bytes) { }
        public void OnOutputCompleted(ulong index) { }
        public void OnTransactionCommitted(in LegacyTransactionSummary summary) { }
        public void OnTransactionAborted() { }
    }
}
