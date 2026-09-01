using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Discovery;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Bsv.LiveProbe.Tests;

[TestClass]
public sealed class ProbeTransportTests
{
    [TestMethod]
    public async Task ReceiveFrameStreamsSplitVersionThroughHandshakeAdapter()
    {
        using var adapter = CreateStartedAdapter(localNonce: 1);
        NetworkAddress.TryCreateIpv4(0, [127, 0, 0, 1], 8333, out var address);
        var frame = ProbeWireEncoder.EncodeVersion(address, address, 1_800_000_000, nonce: 2);
        await using var stream = new ChunkedReadStream(frame, maximumChunkLength: 3);

        var received = await ProbeTransport.ReceiveFrameAsync(
            stream,
            adapter,
            null,
            CancellationToken.None);

        Assert.AreEqual("version", received.Command);
        Assert.IsTrue(received.RetainedPayload.Length <= VersionPayloadCodec.MaximumPayloadLength);
        Assert.AreEqual(2, adapter.PendingOutputCount);
        Assert.IsTrue(adapter.Handshake.HasPeerVersion);
        Assert.AreEqual(2UL, adapter.Handshake.PeerNonce);
    }

    [TestMethod]
    public async Task ReceiveFrameRejectsBadChecksumWithoutHandshakeMutation()
    {
        using var adapter = CreateStartedAdapter(localNonce: 1);
        NetworkAddress.TryCreateIpv4(0, [127, 0, 0, 1], 8333, out var address);
        var frame = ProbeWireEncoder.EncodeVersion(address, address, 1_800_000_000, nonce: 2);
        frame[^1] ^= 0xff;
        await using var stream = new MemoryStream(frame, writable: false);

        await Assert.ThrowsExceptionAsync<InvalidDataException>(() => ProbeTransport.ReceiveFrameAsync(
            stream,
            adapter,
            null,
            CancellationToken.None));

        Assert.IsFalse(adapter.Handshake.HasPeerVersion);
        Assert.AreEqual(BsvHandshakeState.Negotiating, adapter.Handshake.State);
    }

    [TestMethod]
    public async Task OversizedHeadersAreRejectedBeforeCandidateWrite()
    {
        using var adapter = CreateStartedAdapter(localNonce: 1);
        Span<byte> checksum = stackalloc byte[MessageChecksum.Length];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic(
                "headers"u8,
                CandidateArtifact.MaximumHeadersPayloadLength + 1,
                checksum,
                out var header));
        var headerBytes = new byte[MessageHeaderCodec.BasicHeaderLength];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(
                headerBytes,
                ProbeWireEncoder.NetworkMagic,
                header,
                ProbeTransport.MaximumFramePayloadLength,
                out _));
        await using var stream = new MemoryStream(headerBytes, writable: false);
        await using var candidate = new MemoryStream();

        await Assert.ThrowsExceptionAsync<InvalidDataException>(() => ProbeTransport.ReceiveFrameAsync(
            stream,
            adapter,
            candidate,
            CancellationToken.None));

        Assert.AreEqual(0, candidate.Length);
    }

    [TestMethod]
    public async Task OversizedLegacyAddressPayloadIsRejectedBeforeReadingPayload()
    {
        using var adapter = CreateStartedAdapter(localNonce: 1);
        Span<byte> checksum = stackalloc byte[MessageChecksum.Length];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic(
                "addr"u8,
                LegacyAddressPayloadCodec.MaximumPayloadLength + 1,
                checksum,
                out var header));
        var headerBytes = new byte[MessageHeaderCodec.BasicHeaderLength];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(
                headerBytes,
                ProbeWireEncoder.NetworkMagic,
                header,
                ProbeTransport.MaximumFramePayloadLength,
                out _));
        await using var stream = new MemoryStream(headerBytes, writable: false);

        await Assert.ThrowsExceptionAsync<InvalidDataException>(() => ProbeTransport.ReceiveFrameAsync(
            stream,
            adapter,
            null,
            CancellationToken.None));

        Assert.AreEqual(headerBytes.Length, stream.Position);
    }

    private static BsvHandshakeIngressAdapter CreateStartedAdapter(ulong localNonce)
    {
        var adapter = new BsvHandshakeIngressAdapter(
            ProbeWireEncoder.NetworkMagic,
            ProbeTransport.MaximumFramePayloadLength,
            ProbeWireEncoder.MinimumAcceptedPeerProtocolVersion);
        Assert.AreEqual(OperationStatus.Done, adapter.Start(localNonce));
        Span<BsvHandshakeOutput> output = stackalloc BsvHandshakeOutput[1];
        Assert.AreEqual(OperationStatus.Done, adapter.DrainOutputs(output, out var count));
        Assert.AreEqual(1, count);
        return adapter;
    }

    private sealed class ChunkedReadStream(byte[] source, int maximumChunkLength) : MemoryStream(source, writable: false)
    {
        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(buffer.Length, maximumChunkLength)], cancellationToken);
    }
}
