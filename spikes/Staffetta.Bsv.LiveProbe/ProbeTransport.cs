using System.Buffers;
using System.Net.Sockets;
using System.Text;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Bsv.LiveProbe;

internal static class ProbeTransport
{
    internal const int BufferLength = 64 * 1024;
    internal const ulong MaximumFramePayloadLength = ProbeWireEncoder.AdvertisedReceiveLimit;

    internal static async Task<ReceivedFrame> ReceiveFrameAsync(
        Stream stream,
        BsvHandshakeIngressAdapter adapter,
        Stream? headersCandidate,
        CancellationToken cancellationToken)
    {
        var headerBytes = new byte[MessageHeaderCodec.BasicHeaderLength];
        await stream.ReadExactlyAsync(headerBytes, cancellationToken).ConfigureAwait(false);
        var parseStatus = MessageHeaderCodec.TryParse(
            headerBytes,
            ProbeWireEncoder.NetworkMagic,
            MaximumFramePayloadLength,
            out var header,
            out var headerLength);
        if (parseStatus != OperationStatus.Done ||
            headerLength != MessageHeaderCodec.BasicHeaderLength ||
            header.Format != MessageHeaderFormat.Basic)
        {
            throw new InvalidDataException("The peer sent an invalid or unsupported message header.");
        }

        var command = CopyCommand(header.Command);
        var captureHeaders = command == "headers" && headersCandidate is not null;
        if (command == "headers" && header.PayloadLength > CandidateArtifact.MaximumHeadersPayloadLength)
        {
            throw new InvalidDataException("The peer advertised an oversized headers payload.");
        }

        var adapterStatus = adapter.Consume(headerBytes, out var headerBytesConsumed);
        if (headerBytesConsumed != headerBytes.Length ||
            (header.PayloadLength == 0
                ? adapterStatus != OperationStatus.Done
                : adapterStatus != OperationStatus.NeedMoreData))
        {
            throw new InvalidDataException("Handshake ingress rejected the message header.");
        }

        var retainedPayloadLength = command == "version"
            ? checked((int)header.PayloadLength)
            : 0;
        var retainedPayload = retainedPayloadLength == 0 ? [] : new byte[retainedPayloadLength];
        var retainedOffset = 0;
        var rentedBuffer = ArrayPool<byte>.Shared.Rent(BufferLength);
        try
        {
            var remaining = header.PayloadLength;
            while (remaining > 0)
            {
                var chunkLength = (int)Math.Min((ulong)BufferLength, remaining);
                await stream.ReadExactlyAsync(rentedBuffer.AsMemory(0, chunkLength), cancellationToken)
                    .ConfigureAwait(false);
                if (captureHeaders)
                {
                    await headersCandidate!.WriteAsync(
                        rentedBuffer.AsMemory(0, chunkLength),
                        cancellationToken).ConfigureAwait(false);
                }

                if (retainedPayloadLength != 0)
                {
                    rentedBuffer.AsSpan(0, chunkLength).CopyTo(retainedPayload.AsSpan(retainedOffset));
                    retainedOffset += chunkLength;
                }

                adapterStatus = adapter.Consume(rentedBuffer.AsSpan(0, chunkLength), out var bytesConsumed);
                if (bytesConsumed != chunkLength)
                {
                    throw new InvalidDataException("Handshake ingress did not consume the complete payload chunk.");
                }

                remaining -= (uint)chunkLength;
                var expectedStatus = remaining == 0 ? OperationStatus.Done : OperationStatus.NeedMoreData;
                if (adapterStatus != expectedStatus)
                {
                    throw new InvalidDataException("Handshake ingress rejected the message payload.");
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rentedBuffer);
        }

        return new ReceivedFrame(command, header.PayloadLength, retainedPayload, captureHeaders);
    }

    internal static async Task SendAsync(
        Stream stream,
        ReadOnlyMemory<byte> frame,
        CancellationToken cancellationToken)
    {
        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string CopyCommand(MessageCommand command)
    {
        Span<byte> bytes = stackalloc byte[MessageCommand.MaximumLength];
        var status = command.TryCopyTo(bytes, out var bytesWritten);
        return status == OperationStatus.Done
            ? Encoding.ASCII.GetString(bytes[..bytesWritten])
            : throw new InvalidDataException("The peer command could not be copied.");
    }
}

internal sealed record ReceivedFrame(
    string Command,
    ulong PayloadLength,
    byte[] RetainedPayload,
    bool CapturedHeaders);
