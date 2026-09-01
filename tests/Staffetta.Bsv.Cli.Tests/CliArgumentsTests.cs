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
    }
}
