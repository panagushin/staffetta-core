using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Staffetta.Bsv.Cli.Tests;

[TestClass]
public sealed class CliArgumentsTests
{
    [TestMethod]
    [DataRow("node.example:8333")]
    [DataRow("192.0.2.1:8333")]
    [DataRow("[2001:db8::1]:8333")]
    public void HandshakeAcceptsStrictEndpointForms(string endpoint)
    {
        Assert.IsTrue(CliArguments.TryParse(
            ["handshake", "--peer", endpoint],
            out var parsed,
            out var help,
            out var error), error);
        Assert.IsFalse(help);
        Assert.IsNotNull(parsed);
        Assert.AreEqual(ReferenceCliCommand.Handshake, parsed.Command);
    }

    [TestMethod]
    [DataRow("2001:db8::1:8333")]
    [DataRow("[node.example]:8333")]
    [DataRow("https://node.example:8333")]
    [DataRow("node.example/path:8333")]
    [DataRow("node example:8333")]
    [DataRow("node.example:0")]
    [DataRow("node.example:65536")]
    public void HandshakeRejectsAmbiguousOrInvalidEndpoints(string endpoint)
    {
        Assert.IsFalse(CliArguments.TryParse(
            ["handshake", "--peer", endpoint],
            out _,
            out _,
            out _));
    }

    [TestMethod]
    public void CommandsHaveDisjointOptionsAndRejectDuplicates()
    {
        string[][] invalid =
        [
            ["handshake", "--tx-file", "tx.bin", "--peer", "node.example:8333"],
            ["prepare-broadcast", "--tx-file", "tx.bin", "--peer", "node.example:8333"],
            ["prepare-broadcast", "--tx-file", "tx.bin", "--connect-timeout-ms", "5000"],
            ["prepare-broadcast", "--tx-file", "tx.bin", "--handshake-timeout-ms", "30000"],
            ["handshake", "--peer", "node.example:8333", "--peer", "node.example:8334"],
            ["prepare-broadcast", "--tx-file", "a", "--tx-file", "b"],
            ["handshake", "--peer", "node.example:8333", "--broadcast-timeout-ms", "30000"],
            ["broadcast", "--peer", "node.example:8333"],
            ["broadcast", "--tx-file", "tx.bin"],
            ["broadcast", "--peer", "node.example:8333", "--tx-file", "tx.bin", "--broadcast-timeout-ms", "1", "--broadcast-timeout-ms", "2"],
            ["fetch", "--peer", "node.example:8333"],
            ["fetch", "--txid", new string('0', 64)],
            ["fetch", "--peer", "node.example:8333", "--txid", "00"],
            ["fetch", "--peer", "node.example:8333", "--txid", new string('g', 64)],
            ["fetch", "--peer", "node.example:8333", "--txid", new string('0', 64), "--tx-file", "tx.bin"],
            ["handshake", "--peer", "node.example:8333", "--txid", new string('0', 64)],
            ["broadcast", "--peer", "node.example:8333", "--tx-file", "tx.bin", "--fetch-timeout-ms", "1"],
        ];

        foreach (var arguments in invalid)
        {
            Assert.IsFalse(CliArguments.TryParse(arguments, out _, out _, out _), string.Join(' ', arguments));
        }

        Assert.IsTrue(CliArguments.TryParse(
            ["prepare-broadcast", "--tx-file", "tx.bin"],
            out var prepared,
            out _,
            out var error), error);
        Assert.AreEqual(ReferenceCliCommand.PrepareBroadcast, prepared!.Command);

        Assert.IsTrue(CliArguments.TryParse(
            ["broadcast", "--peer", "node.example:8333", "--tx-file", "tx.bin", "--broadcast-timeout-ms", "1234"],
            out var broadcast,
            out _,
            out error), error);
        Assert.AreEqual(ReferenceCliCommand.Broadcast, broadcast!.Command);
        Assert.AreEqual(TimeSpan.FromMilliseconds(1234), broadcast.BroadcastTimeout);

        const string displayTransactionId =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        Assert.IsTrue(CliArguments.TryParse(
            ["fetch", "--peer", "node.example:8333", "--txid", displayTransactionId, "--fetch-timeout-ms", "4321"],
            out var fetch,
            out _,
            out error), error);
        Assert.AreEqual(ReferenceCliCommand.Fetch, fetch!.Command);
        Assert.AreEqual(displayTransactionId, fetch.TransactionId!.Value.ToDisplayHex());
        Assert.AreEqual(TimeSpan.FromMilliseconds(4321), fetch.FetchTimeout);
    }
}
