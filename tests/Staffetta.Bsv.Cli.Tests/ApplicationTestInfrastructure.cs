using System.Buffers;
using System.Net;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Messages;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Bsv.Cli.Tests;

internal sealed class FakePeerConnector : IPeerConnector
{
    private readonly Func<CancellationToken, ValueTask<IPeerConnection>> _connect;

    internal FakePeerConnector(FakePeerConnection connection)
        : this(_ => ValueTask.FromResult<IPeerConnection>(connection))
    {
    }

    internal FakePeerConnector(Func<CancellationToken, ValueTask<IPeerConnection>> connect) =>
        _connect = connect;

    internal int CallCount { get; private set; }

    public ValueTask<IPeerConnection> ConnectAsync(PeerEndpoint endpoint, CancellationToken cancellationToken)
    {
        CallCount++;
        return _connect(cancellationToken);
    }
}

internal sealed class FakePeerConnection : IPeerConnection
{
    private readonly TaskCompletionSource _disposedSignal =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _disposed;

    internal FakePeerConnection(byte[] input, bool endWithEof = false)
    {
        PeerStream = new ScriptedDuplexStream(input, endWithEof);
    }

    internal ScriptedDuplexStream PeerStream { get; }

    public Stream Stream => PeerStream;

    public IPAddress RemoteAddress { get; } = IPAddress.Parse("192.0.2.10");

    public int RemotePort => 8333;

    public string RemoteDisplay => "192.0.2.10:8333";

    internal int AbortCount { get; private set; }

    internal int DisposeCount { get; private set; }

    internal Task Disposed => _disposedSignal.Task;

    public void Abort()
    {
        AbortCount++;
        PeerStream.Abort();
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            DisposeCount++;
            PeerStream.Dispose();
            _disposedSignal.TrySetResult();
        }

        return ValueTask.CompletedTask;
    }
}

internal sealed class ScriptedDuplexStream : Stream
{
    private readonly byte[] _input;
    private readonly bool _endWithEof;
    private readonly MemoryStream _written = new();
    private readonly TaskCompletionSource _readPending =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _offset;
    private bool _aborted;

    internal ScriptedDuplexStream(byte[] input, bool endWithEof)
    {
        _input = input;
        _endWithEof = endWithEof;
    }

    internal Task ReadPending => _readPending.Task;

    internal byte[] WrittenBytes => _written.ToArray();

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        if (_offset < _input.Length)
        {
            buffer.Span[0] = _input[_offset++];
            return ValueTask.FromResult(1);
        }

        if (_endWithEof || _aborted)
        {
            return ValueTask.FromResult(0);
        }

        _readPending.TrySetResult();
        return AwaitCancellationAsync(cancellationToken);
    }

    public override ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _written.Write(buffer.Span);
        return ValueTask.CompletedTask;
    }

    internal void Abort()
    {
        _aborted = true;
        _readPending.TrySetResult();
    }

    public override void Flush() { }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) =>
        _written.Write(buffer, offset, count);

    private static async ValueTask<int> AwaitCancellationAsync(CancellationToken cancellationToken)
    {
        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
        return 0;
    }
}

internal sealed class TestRuntime : IReferenceCliRuntime
{
    private readonly Queue<Func<CancellationToken, Task>> _delays;

    internal TestRuntime(params Func<CancellationToken, Task>[] delays) =>
        _delays = new Queue<Func<CancellationToken, Task>>(delays);

    public long GetUnixTimeSeconds() => 1_788_131_200;

    public ulong CreateNonce() => 0x0102_0304_0506_0708;

    public Task DelayAsync(TimeSpan duration, CancellationToken cancellationToken) =>
        _delays.Count == 0
            ? Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken)
            : _delays.Dequeue()(cancellationToken);

    internal static Task Infinite(CancellationToken cancellationToken) =>
        Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);

    internal static Task Immediate(CancellationToken cancellationToken) => Task.CompletedTask;
}

internal static class PeerFrames
{
    private static readonly byte[] MainnetMagic = [0xe3, 0xe1, 0xf3, 0xe8];

    internal static byte[] Ready()
    {
        Span<byte> ipv4 = stackalloc byte[] { 192, 0, 2, 1 };
        _ = NetworkAddress.TryCreateIpv4(1, ipv4, 8333, out var address);
        var version = new VersionPayload(
            VersionPayloadCodec.CurrentProtocolVersion,
            1,
            1_788_131_200,
            address,
            address,
            0x1112_1314_1516_1718,
            "/peer:test/"u8,
            1,
            true);
        var payload = new byte[VersionPayloadCodec.MaximumPayloadLength];
        AssertDone(VersionPayloadCodec.TryWrite(payload, version, out var written));
        return Concat(Encode("version"u8, payload.AsSpan(0, written)), Encode("verack"u8, []));
    }

    internal static byte[] Rejected()
    {
        var readyPrefix = Ready();
        var versionLength = GetFirstFrameLength(readyPrefix);
        Span<byte> payload = stackalloc byte[RejectPayloadCodec.MaximumPayloadLength];
        AssertDone(RejectPayloadCodec.TryWrite(
            payload,
            "version"u8,
            code: 0x10,
            "unsupported"u8,
            [],
            out var payloadLength));
        return Concat(readyPrefix[..versionLength], Encode("reject"u8, payload[..payloadLength]));
    }

    internal static string[] ReadOutboundCommands(byte[] wire)
    {
        var commands = new List<string>();
        var offset = 0;
        Span<byte> command = stackalloc byte[MessageCommand.MaximumLength];
        while (offset < wire.Length)
        {
            var status = MessageHeaderCodec.TryParse(
                wire.AsSpan(offset),
                MainnetMagic,
                16 * 1024 * 1024,
                out var header,
                out var headerLength);
            AssertDone(status);
            AssertDone(header.Command.TryCopyTo(command, out var commandLength));
            commands.Add(System.Text.Encoding.ASCII.GetString(command[..commandLength]));
            offset += checked(headerLength + (int)header.PayloadLength);
        }

        return [.. commands];
    }

    private static byte[] Encode(ReadOnlySpan<byte> command, ReadOnlySpan<byte> payload)
    {
        var checksum = MessageChecksum.Compute(payload);
        Span<byte> checksumBytes = stackalloc byte[MessageChecksum.Length];
        AssertDone(checksum.TryCopyTo(checksumBytes, out _));
        AssertDone(MessageHeader.TryCreateBasic(command, (uint)payload.Length, checksumBytes, out var header));
        var frame = new byte[MessageHeaderCodec.BasicHeaderLength + payload.Length];
        AssertDone(MessageHeaderCodec.TryWrite(
            frame,
            MainnetMagic,
            header,
            16 * 1024 * 1024,
            out var headerLength));
        payload.CopyTo(frame.AsSpan(headerLength));
        return frame;
    }

    private static byte[] Concat(byte[] first, byte[] second)
    {
        var result = new byte[first.Length + second.Length];
        first.CopyTo(result, 0);
        second.CopyTo(result, first.Length);
        return result;
    }

    private static int GetFirstFrameLength(ReadOnlySpan<byte> wire)
    {
        AssertDone(MessageHeaderCodec.TryParse(
            wire,
            MainnetMagic,
            16 * 1024 * 1024,
            out var header,
            out var headerLength));
        return checked(headerLength + (int)header.PayloadLength);
    }

    private static void AssertDone(OperationStatus status)
    {
        if (status != OperationStatus.Done)
        {
            throw new InvalidOperationException($"Fixture codec returned {status}.");
        }
    }
}
