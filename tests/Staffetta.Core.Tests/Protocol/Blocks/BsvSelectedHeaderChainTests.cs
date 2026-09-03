using System.Buffers;
using System.Numerics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Tests.Protocol.Blocks;

[TestClass]
public sealed class BsvSelectedHeaderChainTests
{
    [TestMethod]
    public void PublicTrustedBootstrapAndCandidateUseExistingContextualAuthority()
    {
        var fixture = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "Bsv",
            "headers-mainnet-daa-boundary-503885-504032-20260901.bin"));
        var headers = new BlockHeader[148];
        Assert.AreEqual(OperationStatus.Done, HeadersPayloadCodec.TryParse(fixture, headers, out _));
        var bootstrap = new BsvHeaderCheckpoint[147];
        var work = UInt256.Zero;
        for (var index = 0; index < bootstrap.Length; index++)
        {
            work = work.Add(BlockProofOfWork.GetBlockWork(headers[index].Bits));
            bootstrap[index] = BsvSelectedHeaderChain.Export(new AdmittedBlockHeader(headers[index],
                headers[index].ComputeHash(), 503_885 + index, work));
        }

        Assert.IsTrue(BsvSelectedHeaderChain.TryCreateTrustedBootstrap(bootstrap, out var chain));
        Assert.AreEqual(bootstrap[^1], chain.SelectedTip);
        Assert.IsTrue(chain.IsOnSelectedChain(bootstrap[0].Hash));
        Assert.IsFalse(chain.IsOnSelectedChain(default));
        var originalTip = chain.SelectedTip;
        var candidate = headers[^1];
        var bad = new BlockHeader(candidate.Version, candidate.PreviousBlockHash, candidate.MerkleRoot,
            candidate.Timestamp, candidate.Bits, candidate.Nonce + 1);
        Assert.AreEqual(BsvHeaderCandidateStatus.ConsensusRejected, chain.Add(bad, out var rejected));
        Assert.IsNull(rejected);
        Assert.AreEqual(originalTip, chain.SelectedTip);
        Assert.AreEqual(BsvHeaderCandidateStatus.Admitted, chain.Add(candidate, out var change));
        Assert.IsNotNull(change);
        Assert.AreEqual(originalTip, change.PreviousTip);
        Assert.AreEqual(chain.SelectedTip, change.SelectedTip);
        Assert.AreEqual(originalTip, change.CommonAncestor);
        Assert.AreEqual(1, change.Attached.Length);
        Assert.AreEqual(0, change.Detached.Length);
        Assert.IsFalse(change.IsReorganization);
        Assert.IsTrue(chain.IsOnSelectedChain(candidate.ComputeHash()));
        Assert.AreEqual(BsvHeaderCandidateStatus.Duplicate, chain.Add(candidate, out _));
        Assert.IsFalse(BsvSelectedHeaderChain.TryCreateTrustedBootstrap(bootstrap.AsSpan(1), out _));
        bootstrap[0] = bootstrap[0] with { CumulativeChainWork = BigInteger.One << 256 };
        Assert.IsFalse(BsvSelectedHeaderChain.TryCreateTrustedBootstrap(bootstrap, out _));
        bootstrap[0] = bootstrap[0] with { CumulativeChainWork = -1 };
        Assert.IsFalse(BsvSelectedHeaderChain.TryCreateTrustedBootstrap(bootstrap, out _));
    }
}
