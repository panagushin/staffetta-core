using System.Buffers;
using System.Buffers.Binary;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Bsv.LiveProbe;

internal static class ProbeWireEncoder
{
    internal const int ProtocolVersion = VersionPayloadCodec.CurrentProtocolVersion;
    internal const int MinimumAcceptedPeerProtocolVersion = 70_015;
    internal const uint AdvertisedReceiveLimit = 2 * 1024 * 1024;
    internal const int GetHeadersPayloadLength = sizeof(int) + 1 + Hash256.Length + Hash256.Length;

    internal static ReadOnlySpan<byte> NetworkMagic => [0xe3, 0xe1, 0xf3, 0xe8];

    internal static ReadOnlySpan<byte> UserAgent => "/StaffettaCore:0.0.0-probe/"u8;

    internal static ReadOnlySpan<byte> StreamPolicy => "Default"u8;

    internal static byte[] EncodeVersion(
        NetworkAddress remoteAddress,
        NetworkAddress localAddress,
        long timestampUnixSeconds,
        ulong nonce)
    {
        Span<byte> payload = stackalloc byte[VersionPayloadCodec.MaximumPayloadLength];
        var version = new VersionPayload(
            ProtocolVersion,
            services: 0,
            timestampUnixSeconds,
            remoteAddress,
            localAddress,
            nonce,
            UserAgent,
            startHeight: 0,
            relay: false);
        EnsureDone(VersionPayloadCodec.TryWrite(payload, version, out var payloadLength));
        return EncodeFrame("version"u8, payload[..payloadLength]);
    }

    internal static byte[] EncodeVerack() => EncodeFrame("verack"u8, []);

    internal static byte[] EncodeProtoconf()
    {
        Span<byte> payload = stackalloc byte[1 + sizeof(uint) + 1 + 7];
        EnsureDone(ProtoconfPayloadCodec.TryWrite(
            payload,
            AdvertisedReceiveLimit,
            StreamPolicy,
            includeStreamPolicies: true,
            out var payloadLength));
        return EncodeFrame("protoconf"u8, payload[..payloadLength]);
    }

    internal static byte[] EncodePing(ulong nonce) => EncodePingPong("ping"u8, nonce);

    internal static byte[] EncodePong(ulong nonce) => EncodePingPong("pong"u8, nonce);

    internal static byte[] EncodeGetAddr() => EncodeFrame("getaddr"u8, []);

    internal static byte[] EncodeGetHeaders(Hash256 locator)
    {
        Span<byte> payload = stackalloc byte[GetHeadersPayloadLength];
        BinaryPrimitives.WriteInt32LittleEndian(payload, ProtocolVersion);
        payload[sizeof(int)] = 1;
        EnsureDone(locator.TryCopyWireBytesTo(payload[(sizeof(int) + 1)..], out var locatorLength));
        payload[(sizeof(int) + 1 + locatorLength)..].Clear();
        return EncodeFrame("getheaders"u8, payload);
    }

    private static byte[] EncodePingPong(ReadOnlySpan<byte> command, ulong nonce)
    {
        Span<byte> payload = stackalloc byte[ModernPingPongPayloadCodec.EncodedLength];
        EnsureDone(ModernPingPongPayloadCodec.TryWrite(payload, nonce, out var payloadLength));
        return EncodeFrame(command, payload[..payloadLength]);
    }

    private static byte[] EncodeFrame(ReadOnlySpan<byte> command, ReadOnlySpan<byte> payload)
    {
        var checksum = MessageChecksum.Compute(payload);
        Span<byte> checksumBytes = stackalloc byte[MessageChecksum.Length];
        EnsureDone(checksum.TryCopyTo(checksumBytes, out _));
        EnsureDone(MessageHeader.TryCreateBasic(
            command,
            checked((uint)payload.Length),
            checksumBytes,
            out var header));

        var frame = new byte[MessageHeaderCodec.BasicHeaderLength + payload.Length];
        EnsureDone(MessageHeaderCodec.TryWrite(
            frame,
            NetworkMagic,
            header,
            AdvertisedReceiveLimit,
            out var headerLength));
        payload.CopyTo(frame.AsSpan(headerLength));
        return frame;
    }

    private static void EnsureDone(OperationStatus status)
    {
        if (status != OperationStatus.Done)
        {
            throw new InvalidOperationException($"A probe wire invariant failed with status {status}.");
        }
    }
}
