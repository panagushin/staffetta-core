using System.Buffers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Messages;
using Staffetta.Core.Protocol.Relay;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Transport;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Tests.Protocol.Transport;

internal static class BsvPeerStreamTransportTestInfrastructure
{
    internal const int MinimumProtocolVersion = VersionPayloadCodec.CurrentProtocolVersion;
    internal const ulong MaximumPayloadLength = 16 * 1024 * 1024;

    internal static readonly byte[] NetworkMagic = [0xe3, 0xe1, 0xf3, 0xe8];

    internal static async ValueTask<TransportFixture> CreateReadyAsync(
        IBsvTransactionPayloadSourceProvider transactionSources,
        BsvPeerStreamTransportOptions? options = null,
        uint peerMaximumReceivePayloadLength = (uint)MaximumPayloadLength)
    {
        var peerFrames = Concatenate(
            Concatenate(
                EncodeBasic("version"u8, CreateVersionPayload()),
                EncodeBasic("verack"u8, [])),
            EncodeBasic(
                "protoconf"u8,
                CreateProtoconfPayload(peerMaximumReceivePayloadLength)));
        var stream = new CountingDuplexStream(peerFrames);
        var facts = new CountingFactSink();
        var pump = CreatePump(
            stream,
            facts,
            transactionSources,
            options ?? new BsvPeerStreamTransportOptions(
                readBufferLength: 16 * 1024,
                transactionBufferLength: 16 * 1024,
                maximumWriteLength: 64 * 1024,
                leaveOpen: false));
        Assert.AreEqual(OperationStatus.Done, pump.StartHandshake());
        await RunUntilAsync(pump, () => facts.BecameReadyCount == 1 && !pump.HasLocalWork);
        return new TransportFixture(pump, stream, facts);
    }

    internal static BsvPeerStreamTransportPump CreatePump(
        CountingDuplexStream stream,
        CountingFactSink facts,
        IBsvTransactionPayloadSourceProvider transactionSources,
        BsvPeerStreamTransportOptions options)
    {
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [192, 0, 2, 1], 8333, out var receiving));
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [192, 0, 2, 2], 8333, out var source));
        var local = new BsvPeerLocalHandshakeConfiguration(
            MinimumProtocolVersion,
            services: 1,
            timestampUnixSeconds: 1_788_131_200,
            receiving,
            source,
            nonce: 0x0102_0304_0506_0708,
            "/Staffetta:transport-evidence/"u8,
            startHeight: 948_321,
            relay: true,
            maximumReceivePayloadLength: (uint)MaximumPayloadLength,
            "Default"u8,
            includeStreamPolicies: true);
        return new BsvPeerStreamTransportPump(
            stream,
            NetworkMagic,
            MaximumPayloadLength,
            MinimumProtocolVersion,
            local,
            new NoOpTransactionSink(),
            transactionSources,
            facts,
            options);
    }

    internal static async ValueTask PrepareBroadcastAsync(
        TransportFixture fixture,
        Hash256 transactionId)
    {
        Assert.AreEqual(OperationStatus.Done, fixture.Pump.StartBroadcast(transactionId));
        await RunUntilAsync(fixture.Pump, () => fixture.Facts.AnnouncedCount == 1);
        fixture.Stream.AppendInput(EncodeInventory("getdata"u8, transactionId));
        await RunUntilAsync(fixture.Pump, () => fixture.Facts.RequestedByPeerCount == 1);
    }

    internal static async ValueTask RunUntilAsync(
        BsvPeerStreamTransportPump pump,
        Func<bool> predicate,
        int maximumSteps = 100_000)
    {
        for (var step = 0; step < maximumSteps && !predicate(); step++)
        {
            var result = await pump.StepAsync();
            Assert.AreEqual(
                BsvPeerTransportStepKind.Progress,
                result.Kind,
                $"Unexpected terminal reason: {result.Reason}.");
        }

        Assert.IsTrue(predicate(), "The transport did not reach the expected state.");
    }

    internal static async ValueTask<BsvPeerTransportStepResult> RunUntilTerminalAsync(
        BsvPeerStreamTransportPump pump,
        int maximumSteps = 100_000)
    {
        for (var step = 0; step < maximumSteps; step++)
        {
            var result = await pump.StepAsync();
            if (result.Kind != BsvPeerTransportStepKind.Progress)
            {
                return result;
            }
        }

        Assert.Fail("The transport did not become terminal.");
        return default;
    }

    internal static byte[] EncodeInventory(ReadOnlySpan<byte> command, Hash256 transactionId)
    {
        var payload = new byte[1 + InventoryVectorCodec.EncodedLength];
        var vectors = new[] { new InventoryVector(1, transactionId) };
        Assert.AreEqual(
            OperationStatus.Done,
            InventoryPayloadCodec.TryWrite(
                vectors,
                payload,
                (ulong)payload.Length,
                out var written));
        Assert.AreEqual(payload.Length, written);
        return EncodeBasic(command, payload);
    }

    internal static byte[] CreateVersionPayload()
    {
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [192, 0, 2, 10], 8333, out var receiving));
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [192, 0, 2, 11], 8333, out var source));
        var version = new VersionPayload(
            MinimumProtocolVersion,
            services: 1,
            timestampUnixSeconds: 1_788_131_200,
            receiving,
            source,
            nonce: 0x1112_1314_1516_1718,
            "/Staffetta:evidence-peer/"u8,
            startHeight: 948_321,
            relay: true);
        var payload = new byte[VersionPayloadCodec.MaximumPayloadLength];
        Assert.AreEqual(
            OperationStatus.Done,
            VersionPayloadCodec.TryWrite(payload, version, out var written));
        return payload[..written];
    }

    internal static byte[] CreateProtoconfPayload(uint maximumReceivePayloadLength)
    {
        var payload = new byte[ProtoconfPayloadCodec.MaximumStreamPoliciesLength + 8];
        Assert.AreEqual(
            OperationStatus.Done,
            ProtoconfPayloadCodec.TryWrite(
                payload,
                maximumReceivePayloadLength,
                "Default"u8,
                includeStreamPolicies: true,
                out var written));
        return payload[..written];
    }

    internal static byte[] EncodeBasic(ReadOnlySpan<byte> command, ReadOnlySpan<byte> payload)
    {
        var checksum = MessageChecksum.Compute(payload);
        Span<byte> checksumBytes = stackalloc byte[MessageChecksum.Length];
        Assert.AreEqual(OperationStatus.Done, checksum.TryCopyTo(checksumBytes, out _));
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic(command, (uint)payload.Length, checksumBytes, out var header));
        var frame = new byte[MessageHeaderCodec.BasicHeaderLength + payload.Length];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(
                frame,
                NetworkMagic,
                header,
                MaximumPayloadLength,
                out var headerLength));
        payload.CopyTo(frame.AsSpan(headerLength));
        return frame;
    }

    internal static byte[] Concatenate(byte[] first, byte[] second)
    {
        var result = new byte[first.Length + second.Length];
        first.CopyTo(result, 0);
        second.CopyTo(result, first.Length);
        return result;
    }
}

internal sealed record TransportFixture(
    BsvPeerStreamTransportPump Pump,
    CountingDuplexStream Stream,
    CountingFactSink Facts) : IAsyncDisposable
{
    public ValueTask DisposeAsync() => Pump.DisposeAsync();
}

internal sealed class CountingDuplexStream : Stream
{
    private readonly List<byte> _input;
    private int _inputOffset;

    internal CountingDuplexStream(byte[] input)
    {
        _input = new List<byte>(input);
    }

    internal long WrittenByteCount { get; private set; }

    internal int DisposeCount { get; private set; }

    internal bool ThrowOnRead { get; set; }

    internal bool ThrowOnWrite { get; set; }

    internal CancellationTokenSource? CancelWriteAfterSideEffectWith { get; set; }

    internal bool ThrowOnDispose { get; set; }

    internal int WriteCallCount { get; private set; }

    internal void AppendInput(byte[] bytes) => _input.AddRange(bytes);

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
        cancellationToken.ThrowIfCancellationRequested();
        if (ThrowOnRead)
        {
            throw new IOException("Injected read failure.");
        }

        if (_inputOffset == _input.Count)
        {
            return ValueTask.FromResult(0);
        }

        var length = Math.Min(buffer.Length, _input.Count - _inputOffset);
        for (var index = 0; index < length; index++)
        {
            buffer.Span[index] = _input[_inputOffset + index];
        }

        _inputOffset += length;
        return ValueTask.FromResult(length);
    }

    public override ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        WriteCallCount++;
        if (CancelWriteAfterSideEffectWith is { } cancellation)
        {
            WrittenByteCount += buffer.Length;
            cancellation.Cancel();
            throw new OperationCanceledException(cancellationToken);
        }

        cancellationToken.ThrowIfCancellationRequested();
        WrittenByteCount += buffer.Length;
        if (ThrowOnWrite)
        {
            throw new IOException("Injected ambiguous write failure.");
        }

        return ValueTask.CompletedTask;
    }

    public override async ValueTask DisposeAsync()
    {
        DisposeCount++;
        try
        {
            if (ThrowOnDispose)
            {
                throw new IOException("Injected stream-dispose failure.");
            }
        }
        finally
        {
            await base.DisposeAsync();
        }
    }

    public override void Flush() => throw new NotSupportedException();

    public override int Read(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException();
}

internal sealed class CountingFactSink : IBsvPeerSessionFactSink
{
    internal int BecameReadyCount { get; private set; }

    internal int AnnouncedCount { get; private set; }

    internal int RequestedByPeerCount { get; private set; }

    internal int SentToPeerCount { get; private set; }

    public ValueTask OnHandshakeFactAsync(
        BsvHandshakeOutput output,
        CancellationToken cancellationToken)
    {
        if (output.Kind == BsvHandshakeOutputKind.BecameReady)
        {
            BecameReadyCount++;
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask OnBroadcastFactAsync(
        BsvTransactionBroadcastOutput output,
        CancellationToken cancellationToken)
    {
        switch (output.Kind)
        {
            case BsvTransactionBroadcastOutputKind.Announced:
                AnnouncedCount++;
                break;
            case BsvTransactionBroadcastOutputKind.RequestedByPeer:
                RequestedByPeerCount++;
                break;
            case BsvTransactionBroadcastOutputKind.SentToPeer:
                SentToPeerCount++;
                break;
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask OnFetchFactAsync(
        BsvTransactionFetchOutput output,
        CancellationToken cancellationToken) => ValueTask.CompletedTask;

    public ValueTask OnMonetaryValidationFactAsync(
        BsvTransactionMonetaryValidation validation,
        CancellationToken cancellationToken) => ValueTask.CompletedTask;
}

internal sealed class NoOpTransactionSink : ILegacyTransactionSink
{
    public void OnTransactionStarted(int version, ulong inputCount) { }

    public void OnInputStarted(ulong inputIndex, in OutPoint previousOutput, ulong scriptLength) { }

    public void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script) { }

    public void OnInputCompleted(ulong inputIndex, uint sequence) { }

    public void OnOutputsStarted(ulong outputCount) { }

    public void OnOutputStarted(ulong outputIndex, long valueSatoshis, ulong scriptLength) { }

    public void OnOutputScriptChunk(ulong outputIndex, ReadOnlySpan<byte> script) { }

    public void OnOutputCompleted(ulong outputIndex) { }

    public void OnTransactionCommitted(in LegacyTransactionSummary summary) { }

    public void OnTransactionAborted() { }
}

internal sealed class BufferPayloadSourceProvider : IBsvTransactionPayloadSourceProvider
{
    private readonly IBsvTransactionPayloadSource _source;

    internal BufferPayloadSourceProvider(IBsvTransactionPayloadSource source)
    {
        _source = source;
    }

    internal bool ThrowOnOpen { get; set; }

    public ValueTask<IBsvTransactionPayloadSource?> OpenAsync(
        Hash256 transactionId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (ThrowOnOpen)
        {
            throw new IOException("Injected source-open failure.");
        }

        return ValueTask.FromResult<IBsvTransactionPayloadSource?>(_source);
    }
}

internal sealed class CountingPayloadSource : IBsvTransactionPayloadSource
{
    private readonly byte[]? _payload;
    private int _offset;

    internal CountingPayloadSource(
        Hash256 transactionId,
        ulong length,
        byte[]? payload = null)
    {
        TransactionId = transactionId;
        Length = length;
        _payload = payload;
    }

    public Hash256 TransactionId { get; }

    public ulong Length { get; }

    internal int ReadCount { get; private set; }

    internal int DisposeCount { get; private set; }

    internal bool ThrowOnRead { get; set; }

    internal bool OverReturn { get; set; }

    internal CancellationTokenSource? CancelReadAfterMutationWith { get; set; }

    internal bool ThrowOnDispose { get; set; }

    internal int MutatedByteCount { get; private set; }

    public ValueTask<int> ReadAsync(
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        if (CancelReadAfterMutationWith is { } cancellation)
        {
            ReadCount++;
            destination.Span[0] = 0x5a;
            MutatedByteCount++;
            cancellation.Cancel();
            throw new OperationCanceledException(cancellationToken);
        }

        cancellationToken.ThrowIfCancellationRequested();
        ReadCount++;
        if (ThrowOnRead)
        {
            throw new IOException("Injected source-read failure.");
        }

        if (OverReturn)
        {
            return ValueTask.FromResult(destination.Length + 1);
        }

        if (_payload is null || _offset == _payload.Length)
        {
            return ValueTask.FromResult(0);
        }

        var length = Math.Min(destination.Length, _payload.Length - _offset);
        _payload.AsSpan(_offset, length).CopyTo(destination.Span);
        _offset += length;
        return ValueTask.FromResult(length);
    }

    public ValueTask DisposeAsync()
    {
        DisposeCount++;
        if (ThrowOnDispose)
        {
            throw new IOException("Injected source-dispose failure.");
        }

        return ValueTask.CompletedTask;
    }
}
