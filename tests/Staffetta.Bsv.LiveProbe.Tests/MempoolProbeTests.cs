using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Messages;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Bsv.LiveProbe.Tests;

[TestClass]
public sealed class MempoolProbeTests
{
    private static readonly string[] ExpectedCommands = ["version", "verack", "protoconf", "mempool", "getdata"];
    private static readonly string[] ExpectedControlCommands = ["version", "verack", "protoconf", "getdata"];
    [TestMethod]
    [DataRow(false, true)]
    [DataRow(true, true)]
    [DataRow(false, false)]
    public async Task RequestFetchAndCaptureRequireValidatedFrames(bool corruptTransaction, bool requestMempool)
    {
        var output = Path.Combine(Path.GetTempPath(), $"staffetta-mempool-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(output);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var endpoint = (IPEndPoint)listener.LocalEndpoint;
        var transaction = Transaction();
        var id = Hash256.DoubleSha256(transaction);
        var commands = new List<string>();
        try
        {
            var peerTask = ServeAsync(listener, transaction, id, corruptTransaction, requestMempool, commands, deadline.Token);
            using var client = new TcpClient();
            await client.ConnectAsync(endpoint, deadline.Token);
            await using var stream = client.GetStream();
            var options = new MempoolProbeOptions(endpoint, output, 10, !requestMempool, requestMempool);
            var evidence = new MempoolEvidence(endpoint.ToString(), false, 10);
            if (corruptTransaction)
            {
                await Assert.ThrowsExceptionAsync<InvalidDataException>(() =>
                    MempoolProbe.RunConnectedAsync(options, stream, evidence, deadline.Token));
                Assert.AreEqual(0, evidence.ValidatedTransactions);
                Assert.AreEqual(1, Directory.GetFiles(output, "*.partial").Length);
            }
            else
            {
                await Assert.ThrowsExceptionAsync<EndOfStreamException>(() =>
                    MempoolProbe.RunConnectedAsync(options, stream, evidence, deadline.Token));
                Assert.AreEqual(1, evidence.ValidatedRequestedTransactions);
                Assert.AreEqual(0, Directory.GetFiles(output, "*.partial").Length);
                var captured = Directory.GetFiles(output, "*.wire").Select(File.ReadAllBytes)
                    .Single(bytes => Encoding.ASCII.GetString(bytes, 4, 2) == "tx");
                CollectionAssert.AreEqual(transaction, captured[MessageHeaderCodec.BasicHeaderLength..]);
            }

            await peerTask;
            Assert.AreEqual(requestMempool ? 1 : 0, evidence.MempoolRequests);
            Assert.AreEqual(1, evidence.UniqueTransactionIds);
            Assert.AreEqual(1L, evidence.RepeatedAnnouncements);
            Assert.AreEqual(1, evidence.RequestedTransactions);
            Assert.IsFalse(evidence.CompleteMempoolClaim);
            Assert.IsFalse(evidence.TransactionBroadcast);
            CollectionAssert.AreEqual(requestMempool ? ExpectedCommands : ExpectedControlCommands, commands);
        }
        finally
        {
            await deadline.CancelAsync();
            Directory.Delete(output, recursive: true);
        }
    }

    [TestMethod]
    [DataRow("9")]
    [DataRow("61")]
    [DataRow("999999999")]
    public void DurationOutsideProbeBudgetIsRejected(string seconds)
    {
        Assert.ThrowsException<ArgumentException>(() => MempoolProbeOptions.Parse(
            ["--peer", "192.0.2.1:8333", "--output", "unused", "--seconds", seconds, "--relay", "false"]));
    }

    private static async Task ServeAsync(TcpListener listener, byte[] transaction, Hash256 id,
        bool corruptTransaction, bool requestMempool, List<string> commands, CancellationToken token)
    {
        using var peer = await listener.AcceptTcpClientAsync(token);
        await using var stream = peer.GetStream();
        commands.Add((await ReadFrameAsync(stream, token)).Command);
        var version = ProbeWireEncoder.EncodeVersion(default, default, 1_800_000_000, 123);
        await WriteSplitAsync(stream, version, token);
        await WriteSplitAsync(stream, ProbeWireEncoder.EncodeVerack(), token);
        while (commands[^1] != "protoconf")
        {
            var frame = await ReadFrameAsync(stream, token);
            commands.Add(frame.Command);
            Assert.IsTrue(commands.Count <= 4);
        }

        if (requestMempool)
        {
            commands.Add((await ReadFrameAsync(stream, token)).Command);
            Assert.AreEqual("mempool", commands[^1]);
        }

        var payload = new byte[1 + 2 * InventoryVectorCodec.EncodedLength];
        Assert.AreEqual(OperationStatus.Done, InventoryPayloadCodec.TryWrite(
            [new(1, id), new(1, id)], payload, (ulong)payload.Length, out _));
        await WriteSplitAsync(stream, ProbeWireEncoder.EncodeFrame("inv"u8, payload), token);
        var request = await ReadFrameAsync(stream, token);
        commands.Add(request.Command);
        var expected = new byte[1 + InventoryVectorCodec.EncodedLength];
        Assert.AreEqual(OperationStatus.Done, InventoryPayloadCodec.TryWrite(
            [new(1, id)], expected, (ulong)expected.Length, out _));
        CollectionAssert.AreEqual(expected, request.Payload);
        var txFrame = ProbeWireEncoder.EncodeFrame("tx"u8, transaction);
        if (corruptTransaction)
        {
            txFrame[20] ^= 1;
        }

        await WriteSplitAsync(stream, txFrame, token);
    }

    private static async Task WriteSplitAsync(Stream stream, byte[] bytes, CancellationToken token)
    {
        for (var offset = 0; offset < bytes.Length; offset += 3)
        {
            await stream.WriteAsync(bytes.AsMemory(offset, Math.Min(3, bytes.Length - offset)), token);
        }
    }

    private static async Task<(string Command, byte[] Payload)> ReadFrameAsync(Stream stream, CancellationToken token)
    {
        var bytes = new byte[MessageHeaderCodec.BasicHeaderLength];
        await stream.ReadExactlyAsync(bytes, token);
        Assert.AreEqual(OperationStatus.Done, MessageHeaderCodec.TryParse(bytes, ProbeWireEncoder.NetworkMagic,
            4096, out var header, out _));
        var payload = new byte[(int)header.PayloadLength];
        await stream.ReadExactlyAsync(payload, token);
        return (Encoding.ASCII.GetString(bytes, 4, 12).TrimEnd('\0'), payload);
    }

    private static byte[] Transaction()
    {
        using var memory = new MemoryStream();
        using var writer = new BinaryWriter(memory);
        writer.Write(1);
        writer.Write((byte)1);
        writer.Write(new byte[32]);
        writer.Write(0U);
        writer.Write((byte)0);
        writer.Write(uint.MaxValue);
        writer.Write((byte)1);
        writer.Write(1L);
        writer.Write((byte)1);
        writer.Write((byte)0x51);
        writer.Write(0U);
        return memory.ToArray();
    }
}
