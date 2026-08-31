using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Staffetta.Bsv.LiveProbe.Tests;

[TestClass]
public sealed class ProbeOptionsTests
{
    private const string Locator =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    [TestMethod]
    public void ParseAcceptsOnlyExplicitLiteralPeerAndRequiredOptions()
    {
        var output = Path.Combine(Path.GetTempPath(), "staffetta-probe-options");
        var options = ProbeOptions.Parse(
            ["--output", output, "--peer", "127.0.0.1:8333", "--locator", Locator]);

        Assert.AreEqual("127.0.0.1", options.Peer.Address.ToString());
        Assert.AreEqual(8333, options.Peer.Port);
        Assert.AreEqual(Locator, options.Locator.ToDisplayHex());
        Assert.AreEqual(Path.GetFullPath(output), options.OutputDirectory);
    }

    [DataRow("node.example:8333")]
    [DataRow("127.0.0.1:0")]
    [DataRow("127.0.0.1:65536")]
    [DataRow("[::1]:8333")]
    [TestMethod]
    public void ParseRejectsNonLiteralOrAmbiguousPeers(string peer)
    {
        Assert.ThrowsException<ArgumentException>(() => ProbeOptions.Parse(
            ["--peer", peer, "--locator", Locator, "--output", "unused"]));
    }

    [TestMethod]
    public void ParseRejectsDuplicateOptionsAndMalformedLocator()
    {
        Assert.ThrowsException<ArgumentException>(() => ProbeOptions.Parse(
            ["--peer", "127.0.0.1:8333", "--peer", "127.0.0.2:8333", "--output", "unused"]));
        Assert.ThrowsException<ArgumentException>(() => ProbeOptions.Parse(
            ["--peer", "127.0.0.1:8333", "--locator", "not-a-hash", "--output", "unused"]));
    }
}
