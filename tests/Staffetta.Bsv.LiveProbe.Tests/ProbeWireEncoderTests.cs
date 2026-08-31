using System.Buffers;
using System.Buffers.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Bsv.LiveProbe.Tests;

[TestClass]
public sealed class ProbeWireEncoderTests
{
    [TestMethod]
    public void VersionMatchesLiveProbeProfileAndChecksum()
    {
        NetworkAddress.TryCreateIpv4(0, [57, 129, 76, 3], 8333, out var remote);
        NetworkAddress.TryCreateIpv4(0, [192, 0, 2, 1], 50_000, out var local);
        var frame = ProbeWireEncoder.EncodeVersion(remote, local, 1_800_000_000, 42);

        var payload = ParseFrame(frame, "version");
        Assert.AreEqual(
            OperationStatus.Done,
            VersionPayloadCodec.TryParse(payload, out var version, out var consumed));
        Assert.AreEqual(payload.Length, consumed);
        Assert.AreEqual(VersionPayloadCodec.CurrentProtocolVersion, version.ProtocolVersion);
        Assert.AreEqual(42UL, version.Nonce);
        Assert.AreEqual(1_800_000_000L, version.TimestampUnixSeconds);
        Assert.IsTrue(version.UserAgent.SequenceEqual("/StaffettaCore:0.0.0-probe/"u8));
        Assert.IsFalse(version.Relay);
        Assert.IsFalse(version.HasAssociationId);
    }

    [TestMethod]
    public void ProtoconfReproducesBaselineTwoFieldPolicy()
    {
        var payload = ParseFrame(ProbeWireEncoder.EncodeProtoconf(), "protoconf");

        Assert.AreEqual(
            OperationStatus.Done,
            ProtoconfPayloadCodec.TryParse(payload, out var protoconf, out var consumed));
        Assert.AreEqual(payload.Length, consumed);
        Assert.AreEqual<ulong>(2, protoconf.FieldCount);
        Assert.AreEqual<uint>(2 * 1024 * 1024, protoconf.MaximumReceivePayloadLength);
        Assert.IsTrue(protoconf.StreamPolicies.SequenceEqual("Default"u8));
    }

    [TestMethod]
    public void GetHeadersUsesOneWireOrderLocatorAndZeroStopHash()
    {
        const string displayHash =
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        var wireHash = Convert.FromHexString(displayHash);
        wireHash.AsSpan().Reverse();
        Assert.AreEqual(OperationStatus.Done, Hash256.TryCreate(wireHash, out var locator));

        var payload = ParseFrame(ProbeWireEncoder.EncodeGetHeaders(locator), "getheaders");
        Assert.AreEqual(ProbeWireEncoder.GetHeadersPayloadLength, payload.Length);
        Assert.AreEqual(VersionPayloadCodec.CurrentProtocolVersion, BinaryPrimitives.ReadInt32LittleEndian(payload));
        Assert.AreEqual(1, payload[sizeof(int)]);
        Assert.IsTrue(payload.Slice(sizeof(int) + 1, Hash256.Length).SequenceEqual(wireHash));
        Assert.IsTrue(payload[(sizeof(int) + 1 + Hash256.Length)..].ToArray().All(value => value == 0));
    }

    [TestMethod]
    public void FixedControlFramesHaveExactCommandsAndPayloads()
    {
        Assert.AreEqual(0, ParseFrame(ProbeWireEncoder.EncodeVerack(), "verack").Length);
        Assert.AreEqual(8, ParseFrame(ProbeWireEncoder.EncodePing(42), "ping").Length);
        Assert.AreEqual(8, ParseFrame(ProbeWireEncoder.EncodePong(42), "pong").Length);
    }

    private static ReadOnlySpan<byte> ParseFrame(byte[] frame, string expectedCommand)
    {
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryParse(
                frame,
                ProbeWireEncoder.NetworkMagic,
                ProbeTransport.MaximumFramePayloadLength,
                out var header,
                out var headerLength));
        Assert.IsTrue(header.Command.Equals(System.Text.Encoding.ASCII.GetBytes(expectedCommand)));
        var payload = frame.AsSpan(headerLength);
        Assert.AreEqual((ulong)payload.Length, header.PayloadLength);
        Assert.AreEqual(MessageChecksum.Compute(payload), header.PayloadChecksum);
        return payload;
    }
}
