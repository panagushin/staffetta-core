using System.Buffers;
using System.Net;
using Staffetta.Core.Protocol.Cryptography;
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
    private readonly object _gate = new();
    private readonly Queue<byte> _input = new();
    private readonly bool _endWithEof;
    private readonly MemoryStream _written = new();
    private readonly TaskCompletionSource _readPending =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private PendingRead? _pendingRead;
    private bool _aborted;
    private int _failNextWrite;

    internal ScriptedDuplexStream(byte[] input, bool endWithEof)
    {
        _endWithEof = endWithEof;
        foreach (var value in input)
        {
            _input.Enqueue(value);
        }
    }

    internal Task ReadPending => _readPending.Task;

    internal bool IsReadPending
    {
        get
        {
            lock (_gate)
            {
                return _pendingRead is not null;
            }
        }
    }

    internal byte[] WrittenBytes
    {
        get
        {
            lock (_gate)
            {
                return _written.ToArray();
            }
        }
    }

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
        lock (_gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_input.Count != 0)
            {
                return ValueTask.FromResult(CopyInput(buffer.Span));
            }

            if (_endWithEof || _aborted)
            {
                return ValueTask.FromResult(0);
            }

            _readPending.TrySetResult();
            var pending = new PendingRead(buffer);
            _pendingRead = pending;
            pending.Registration = cancellationToken.Register(
                static state => ((ScriptedDuplexStream)state!).CancelPendingRead(),
                this);
            return new ValueTask<int>(pending.Completion.Task);
        }
    }

    public override ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.Exchange(ref _failNextWrite, 0) != 0)
        {
            return ValueTask.FromException(new IOException("scripted write failure"));
        }

        lock (_gate)
        {
            _written.Write(buffer.Span);
        }
        return ValueTask.CompletedTask;
    }

    internal void FailNextWrite() => Interlocked.Exchange(ref _failNextWrite, 1);

    internal void Abort()
    {
        PendingRead? pending;
        lock (_gate)
        {
            _aborted = true;
            pending = _pendingRead;
            _pendingRead = null;
        }

        pending?.Completion.TrySetResult(0);
        pending?.Registration.Dispose();
        _readPending.TrySetResult();
    }

    internal void AppendInput(byte[] input)
    {
        PendingRead? pending;
        lock (_gate)
        {
            foreach (var value in input)
            {
                _input.Enqueue(value);
            }

            pending = _pendingRead;
            _pendingRead = null;
            if (pending is not null)
            {
                _ = CopyInput(pending.Buffer.Span);
            }
        }

        pending?.Completion.TrySetResult(input.Length);
        pending?.Registration.Dispose();
    }

    public override void Flush() { }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) =>
        _written.Write(buffer, offset, count);

    private void CancelPendingRead()
    {
        PendingRead? pending;
        lock (_gate)
        {
            pending = _pendingRead;
            _pendingRead = null;
        }

        pending?.Completion.TrySetCanceled();
    }

    private int CopyInput(Span<byte> destination)
    {
        var count = Math.Min(destination.Length, _input.Count);
        for (var index = 0; index < count; index++)
        {
            destination[index] = _input.Dequeue();
        }

        return count;
    }

    private sealed class PendingRead(Memory<byte> buffer)
    {
        internal Memory<byte> Buffer { get; } = buffer;
        internal TaskCompletionSource<int> Completion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal CancellationTokenRegistration Registration { get; set; }
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

    internal static byte[] ReadyThen(params byte[][] frames)
    {
        var result = Ready();
        foreach (var frame in frames)
        {
            result = Concat(result, frame);
        }

        return result;
    }

    internal static byte[] Inventory(string command, Hash256 transactionId)
    {
        var payload = new byte[1 + InventoryVectorCodec.EncodedLength];
        var vectors = new[] { new InventoryVector(1, transactionId) };
        AssertDone(InventoryPayloadCodec.TryWrite(vectors, payload, (ulong)payload.Length, out var written));
        return Encode(System.Text.Encoding.ASCII.GetBytes(command), payload.AsSpan(0, written));
    }

    internal static byte[] TransactionReject(Hash256 transactionId)
    {
        Span<byte> hash = stackalloc byte[Hash256.Length];
        AssertDone(transactionId.TryCopyWireBytesTo(hash, out _));
        Span<byte> payload = stackalloc byte[RejectPayloadCodec.MaximumPayloadLength];
        AssertDone(RejectPayloadCodec.TryWrite(
            payload,
            "tx"u8,
            code: 0x10,
            "rejected"u8,
            hash,
            out var payloadLength));
        return Encode("reject"u8, payload[..payloadLength]);
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

    internal static byte[] ReadOutboundPayload(byte[] wire, string expectedCommand)
    {
        var offset = 0;
        Span<byte> command = stackalloc byte[MessageCommand.MaximumLength];
        while (offset < wire.Length)
        {
            AssertDone(MessageHeaderCodec.TryParse(
                wire.AsSpan(offset),
                MainnetMagic,
                ulong.MaxValue,
                out var header,
                out var headerLength));
            AssertDone(header.Command.TryCopyTo(command, out var commandLength));
            var length = checked((int)header.PayloadLength);
            if (System.Text.Encoding.ASCII.GetString(command[..commandLength]) == expectedCommand)
            {
                return wire.AsSpan(offset + headerLength, length).ToArray();
            }

            offset += checked(headerLength + length);
        }

        throw new InvalidOperationException($"Outbound command '{expectedCommand}' was not found.");
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
