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

[TestClass]
public sealed class BsvPeerStreamTransportPumpTests
{
    private const int MinimumProtocolVersion = VersionPayloadCodec.CurrentProtocolVersion;
    private const ulong LocalNonce = 0x0102_0304_0506_0708;
    private const ulong PeerNonce = 0x1112_1314_1516_1718;
    private const ulong MaximumPayloadLength = 8 * 1024 * 1024;

    private static readonly byte[] NetworkMagic = [0xe3, 0xe1, 0xf3, 0xe8];
    private static readonly string[] ExpectedHandshakeCommands = ["version", "verack", "protoconf"];

    [TestMethod]
    public async Task CoalescedHandshakePreservesRemainderAndWritesExactFramesOneByteAtATime()
    {
        var peerFrames = Concatenate(
            EncodeBasic("version"u8, CreateVersionPayload(PeerNonce)),
            EncodeBasic("verack"u8, []));
        var stream = new FakeDuplexStream(peerFrames, maximumReadLength: peerFrames.Length);
        var facts = new RecordingFactSink();
        await using var pump = CreatePump(
            stream,
            facts,
            new MissingSourceProvider(),
            new BsvPeerStreamTransportOptions(
                readBufferLength: 4096,
                transactionBufferLength: 1024,
                maximumWriteLength: 1,
                leaveOpen: true));

        Assert.AreEqual(OperationStatus.Done, pump.StartHandshake());
        await RunUntilAsync(
            pump,
            () => facts.HasHandshake(BsvHandshakeOutputKind.BecameReady));

        Assert.AreEqual(BsvHandshakeState.Ready, pump.HandshakeState);
        Assert.AreEqual(1, stream.ReadCallCount);
        CollectionAssert.AreEqual(
            ExpectedHandshakeCommands,
            ReadCommands(stream.WrittenBytes));
    }

    [TestMethod]
    public async Task BytewisePeerReadsCompleteHandshakeWithoutReplayOrZeroProgress()
    {
        var peerFrames = Concatenate(
            EncodeBasic("version"u8, CreateVersionPayload(PeerNonce)),
            EncodeBasic("verack"u8, []));
        var stream = new FakeDuplexStream(peerFrames, maximumReadLength: 1);
        var facts = new RecordingFactSink();
        await using var pump = CreatePump(
            stream,
            facts,
            new MissingSourceProvider(),
            new BsvPeerStreamTransportOptions(
                readBufferLength: 64,
                transactionBufferLength: 64,
                maximumWriteLength: 64,
                leaveOpen: true));

        Assert.AreEqual(OperationStatus.Done, pump.StartHandshake());
        await RunUntilAsync(
            pump,
            () => facts.HasHandshake(BsvHandshakeOutputKind.BecameReady));

        Assert.AreEqual(BsvHandshakeState.Ready, pump.HandshakeState);
        Assert.AreEqual(peerFrames.Length, stream.ReadCallCount);
    }

    [TestMethod]
    public async Task BroadcastStreamsMultiMegabytePayloadAndPublishesSentOnlyAfterFinalAck()
    {
        var stream = CreateHandshakeStream();
        var facts = new RecordingFactSink();
        var payload = new byte[2 * 1024 * 1024 + 17];
        for (var index = 0; index < payload.Length; index++)
        {
            payload[index] = (byte)(index * 31);
        }

        var transactionId = Hash256.DoubleSha256(payload);
        var source = new BufferTransactionSource(transactionId, payload, maximumReadLength: 8191)
        {
            LengthAfterFirstRead = (ulong)payload.Length + 10_000,
        };
        await using var pump = CreatePump(
            stream,
            facts,
            new SingleSourceProvider(source),
            new BsvPeerStreamTransportOptions(
                readBufferLength: 4096,
                transactionBufferLength: 16 * 1024,
                maximumWriteLength: 4093,
                leaveOpen: true));
        Assert.AreEqual(OperationStatus.Done, pump.StartHandshake());
        await RunUntilAsync(
            pump,
            () => facts.HasHandshake(BsvHandshakeOutputKind.BecameReady) && !pump.HasLocalWork);

        Assert.AreEqual(OperationStatus.Done, pump.StartBroadcast(transactionId));
        await RunUntilAsync(
            pump,
            () => facts.HasBroadcast(BsvTransactionBroadcastOutputKind.Announced));
        stream.AppendInput(EncodeInventory("getdata"u8, transactionId));

        var sawTransactionBytesBeforeFact = false;
        var initialWireLength = stream.WrittenBytes.Count;
        await RunUntilAsync(
            pump,
            () => facts.HasBroadcast(BsvTransactionBroadcastOutputKind.SentToPeer),
            afterStep: () =>
            {
                if (stream.WrittenBytes.Count > initialWireLength &&
                    !facts.HasBroadcast(BsvTransactionBroadcastOutputKind.SentToPeer))
                {
                    sawTransactionBytesBeforeFact = true;
                }
            });

        Assert.IsTrue(sawTransactionBytesBeforeFact);
        Assert.IsTrue(facts.HasBroadcast(BsvTransactionBroadcastOutputKind.RequestedByPeer));
        Assert.IsTrue(facts.HasBroadcast(BsvTransactionBroadcastOutputKind.SentToPeer));
        Assert.AreEqual((ulong)payload.Length, source.BytesRead);
        Assert.AreEqual(1, source.LengthReadCount);
        Assert.AreEqual(1, source.DisposeCount);
        AssertTransactionFrame(stream.WrittenBytes, transactionId, payload);
    }

    [TestMethod]
    public async Task PrematureTransactionSourceEndFaultsWithoutSentFact()
    {
        var stream = CreateHandshakeStream();
        var facts = new RecordingFactSink();
        byte[] available = [1, 2, 3, 4];
        var transactionId = Hash256.DoubleSha256(available);
        var source = new BufferTransactionSource(
            transactionId,
            available,
            declaredLength: 8,
            maximumReadLength: 4);
        await using var pump = CreatePump(
            stream,
            facts,
            new SingleSourceProvider(source),
            new BsvPeerStreamTransportOptions(leaveOpen: true));
        Assert.AreEqual(OperationStatus.Done, pump.StartHandshake());
        await RunUntilAsync(
            pump,
            () => facts.HasHandshake(BsvHandshakeOutputKind.BecameReady) && !pump.HasLocalWork);
        Assert.AreEqual(OperationStatus.Done, pump.StartBroadcast(transactionId));
        await RunUntilAsync(
            pump,
            () => facts.HasBroadcast(BsvTransactionBroadcastOutputKind.Announced));
        stream.AppendInput(EncodeInventory("getdata"u8, transactionId));

        var terminal = await RunUntilTerminalAsync(pump);

        Assert.AreEqual(BsvPeerTransportStepKind.Faulted, terminal.Kind);
        Assert.AreEqual(
            BsvPeerTransportTerminalReason.TransactionSourceContractViolation,
            terminal.Reason);
        Assert.IsFalse(facts.HasBroadcast(BsvTransactionBroadcastOutputKind.SentToPeer));
        Assert.AreEqual(1, source.DisposeCount);
    }

    [TestMethod]
    public async Task WriteSideEffectThenExceptionAcknowledgesNothingAndTerminalizes()
    {
        var stream = CreateHandshakeStream();
        var facts = new RecordingFactSink();
        await using var pump = CreatePump(
            stream,
            facts,
            new MissingSourceProvider(),
            new BsvPeerStreamTransportOptions(maximumWriteLength: 1, leaveOpen: true));
        Assert.AreEqual(OperationStatus.Done, pump.StartHandshake());
        await RunUntilAsync(
            pump,
            () => facts.HasHandshake(BsvHandshakeOutputKind.BecameReady) && !pump.HasLocalWork);
        var transactionId = Hash256.DoubleSha256("write-failure"u8);
        Assert.AreEqual(OperationStatus.Done, pump.StartBroadcast(transactionId));
        stream.FailNextWriteAfterSideEffect = true;

        var terminal = await RunUntilTerminalAsync(pump);

        Assert.AreEqual(BsvPeerTransportStepKind.Faulted, terminal.Kind);
        Assert.AreEqual(BsvPeerTransportTerminalReason.TransportWriteFailure, terminal.Reason);
        Assert.IsFalse(facts.HasBroadcast(BsvTransactionBroadcastOutputKind.Announced));
    }

    [TestMethod]
    public async Task StartCommandRejectsBothRetainedFrameAndConsumedPartialFrame()
    {
        var retainedFrame = EncodeBasic("ping"u8, CreateNoncePayload(42));
        var stream = CreateHandshakeStream();
        var facts = new RecordingFactSink();
        await using var pump = CreatePump(
            stream,
            facts,
            new MissingSourceProvider(),
            new BsvPeerStreamTransportOptions(leaveOpen: true));
        Assert.AreEqual(OperationStatus.Done, pump.StartHandshake());
        await RunUntilAsync(
            pump,
            () => facts.HasHandshake(BsvHandshakeOutputKind.BecameReady) && !pump.HasLocalWork);
        stream.AppendInput(retainedFrame);
        var readsBeforeRetainedFrame = stream.ReadCallCount;
        await RunUntilAsync(pump, () => stream.ReadCallCount != readsBeforeRetainedFrame);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            pump.StartBroadcast(Hash256.DoubleSha256("retained"u8)));

        var partialStream = CreateHandshakeStream();
        var partialFacts = new RecordingFactSink();
        await using var partialPump = CreatePump(
            partialStream,
            partialFacts,
            new MissingSourceProvider(),
            new BsvPeerStreamTransportOptions(leaveOpen: true));
        Assert.AreEqual(OperationStatus.Done, partialPump.StartHandshake());
        await RunUntilAsync(
            partialPump,
            () => partialFacts.HasHandshake(BsvHandshakeOutputKind.BecameReady) &&
                !partialPump.HasLocalWork);
        partialStream.AppendInput(retainedFrame[..10]);
        var readsBeforePrefix = partialStream.ReadCallCount;
        await RunUntilAsync(partialPump, () => partialStream.ReadCallCount != readsBeforePrefix);
        Assert.AreEqual(
            BsvPeerTransportStepKind.Progress,
            (await partialPump.StepAsync()).Kind);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            partialPump.StartBroadcast(Hash256.DoubleSha256("partial"u8)));
    }

    [TestMethod]
    public async Task WrongTransactionBytesAreClassifiedAtFinalAcknowledgement()
    {
        var stream = CreateHandshakeStream();
        var facts = new RecordingFactSink();
        byte[] actualPayload = [1, 2, 3, 4, 5];
        var requestedId = Hash256.DoubleSha256("different-payload"u8);
        var source = new BufferTransactionSource(requestedId, actualPayload);
        await using var pump = CreatePump(
            stream,
            facts,
            new SingleSourceProvider(source),
            new BsvPeerStreamTransportOptions(maximumWriteLength: 1, leaveOpen: true));
        Assert.AreEqual(OperationStatus.Done, pump.StartHandshake());
        await RunUntilAsync(
            pump,
            () => facts.HasHandshake(BsvHandshakeOutputKind.BecameReady) && !pump.HasLocalWork);
        Assert.AreEqual(OperationStatus.Done, pump.StartBroadcast(requestedId));
        await RunUntilAsync(
            pump,
            () => facts.HasBroadcast(BsvTransactionBroadcastOutputKind.Announced));
        stream.AppendInput(EncodeInventory("getdata"u8, requestedId));

        var terminal = await RunUntilTerminalAsync(pump);

        Assert.AreEqual(BsvPeerTransportTerminalReason.TransactionHashMismatch, terminal.Reason);
        Assert.IsFalse(facts.HasBroadcast(BsvTransactionBroadcastOutputKind.SentToPeer));
    }

    [TestMethod]
    public async Task CaughtWriteCallbackReentryTerminalizesBeforeLeaseAcknowledgement()
    {
        var stream = CreateHandshakeStream();
        var facts = new RecordingFactSink();
        await using var pump = CreatePump(
            stream,
            facts,
            new MissingSourceProvider(),
            new BsvPeerStreamTransportOptions(maximumWriteLength: 1, leaveOpen: true));
        Assert.AreEqual(OperationStatus.Done, pump.StartHandshake());
        await RunUntilAsync(
            pump,
            () => facts.HasHandshake(BsvHandshakeOutputKind.BecameReady) && !pump.HasLocalWork);
        var transactionId = Hash256.DoubleSha256("reentrant-write"u8);
        Assert.AreEqual(OperationStatus.Done, pump.StartBroadcast(transactionId));
        stream.OnNextWrite = () =>
            Assert.AreEqual(OperationStatus.InvalidData, pump.StartFetch(transactionId));

        var terminal = await RunUntilTerminalAsync(pump);

        Assert.AreEqual(BsvPeerTransportTerminalReason.DependencyReentry, terminal.Reason);
        Assert.IsFalse(facts.HasBroadcast(BsvTransactionBroadcastOutputKind.Announced));
    }

    [TestMethod]
    public async Task CaughtFactSinkReentryTerminalizesWithoutProcessingLaterWork()
    {
        var stream = CreateHandshakeStream();
        var facts = new RecordingFactSink();
        await using var pump = CreatePump(
            stream,
            facts,
            new MissingSourceProvider(),
            new BsvPeerStreamTransportOptions(leaveOpen: true));
        Assert.AreEqual(OperationStatus.Done, pump.StartHandshake());
        await RunUntilAsync(
            pump,
            () => facts.HasHandshake(BsvHandshakeOutputKind.BecameReady) && !pump.HasLocalWork);
        var transactionId = Hash256.DoubleSha256("reentrant-fact"u8);
        facts.OnBroadcastFact = output =>
        {
            if (output.Kind == BsvTransactionBroadcastOutputKind.Announced)
            {
                Assert.AreEqual(OperationStatus.InvalidData, pump.StartFetch(transactionId));
            }
        };
        Assert.AreEqual(OperationStatus.Done, pump.StartBroadcast(transactionId));

        var terminal = await RunUntilTerminalAsync(pump);

        Assert.AreEqual(BsvPeerTransportTerminalReason.DependencyReentry, terminal.Reason);
        Assert.IsTrue(facts.HasBroadcast(BsvTransactionBroadcastOutputKind.Announced));
    }

    [TestMethod]
    public async Task TerminalHandshakeDoesNotReadAgainAndCleanupRunsOnce()
    {
        var frame = EncodeBasic(
            "version"u8,
            CreateVersionPayload(PeerNonce, MinimumProtocolVersion - 1));
        var stream = new FakeDuplexStream(frame, frame.Length);
        var facts = new RecordingFactSink();
        await using var pump = CreatePump(
            stream,
            facts,
            new MissingSourceProvider(),
            new BsvPeerStreamTransportOptions(leaveOpen: false));
        Assert.AreEqual(OperationStatus.Done, pump.StartHandshake());

        var terminal = await RunUntilTerminalAsync(pump);
        await pump.DisposeAsync();

        Assert.AreEqual(BsvPeerTransportTerminalReason.HandshakeTerminated, terminal.Reason);
        Assert.AreEqual(1, stream.ReadCallCount);
        Assert.AreEqual(1, stream.DisposeCount);
    }

    [TestMethod]
    public async Task SourceDisposeReentryDeliversCommittedFactThenTerminalizes()
    {
        var stream = CreateHandshakeStream();
        var facts = new RecordingFactSink();
        byte[] payload = [1, 2, 3, 4];
        var transactionId = Hash256.DoubleSha256(payload);
        var source = new BufferTransactionSource(transactionId, payload);
        await using var pump = CreatePump(
            stream,
            facts,
            new SingleSourceProvider(source),
            new BsvPeerStreamTransportOptions(leaveOpen: true));
        source.OnDispose = () =>
            Assert.AreEqual(OperationStatus.InvalidData, pump.StartFetch(transactionId));
        Assert.AreEqual(OperationStatus.Done, pump.StartHandshake());
        await RunUntilAsync(
            pump,
            () => facts.HasHandshake(BsvHandshakeOutputKind.BecameReady) && !pump.HasLocalWork);
        Assert.AreEqual(OperationStatus.Done, pump.StartBroadcast(transactionId));
        await RunUntilAsync(
            pump,
            () => facts.HasBroadcast(BsvTransactionBroadcastOutputKind.Announced));
        stream.AppendInput(EncodeInventory("getdata"u8, transactionId));

        var terminal = await RunUntilTerminalAsync(pump);

        Assert.AreEqual(BsvPeerTransportTerminalReason.DependencyReentry, terminal.Reason);
        Assert.IsTrue(facts.HasBroadcast(BsvTransactionBroadcastOutputKind.SentToPeer));
        Assert.AreEqual(1, source.DisposeCount);
    }

    [TestMethod]
    public async Task CancellationCannotEraseAnAlreadyCommittedWriteFact()
    {
        var stream = CreateHandshakeStream();
        var facts = new RecordingFactSink();
        await using var pump = CreatePump(
            stream,
            facts,
            new MissingSourceProvider(),
            new BsvPeerStreamTransportOptions(leaveOpen: true));
        Assert.AreEqual(OperationStatus.Done, pump.StartHandshake());
        await RunUntilAsync(
            pump,
            () => facts.HasHandshake(BsvHandshakeOutputKind.BecameReady) && !pump.HasLocalWork);
        var transactionId = Hash256.DoubleSha256("committed-cancellation"u8);
        Assert.AreEqual(OperationStatus.Done, pump.StartBroadcast(transactionId));

        Assert.AreEqual(BsvPeerTransportStepKind.Progress, (await pump.StepAsync()).Kind);
        Assert.AreEqual(BsvPeerTransportStepKind.Progress, (await pump.StepAsync()).Kind);
        Assert.AreEqual(BsvPeerTransportStepKind.Progress, (await pump.StepAsync()).Kind);
        Assert.AreEqual(BsvPeerTransportStepKind.Progress, (await pump.StepAsync()).Kind);
        Assert.IsFalse(facts.HasBroadcast(BsvTransactionBroadcastOutputKind.Announced));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var factStep = await pump.StepAsync(cancellation.Token);

        Assert.AreEqual(BsvPeerTransportStepKind.Progress, factStep.Kind);
        Assert.IsTrue(facts.HasBroadcast(BsvTransactionBroadcastOutputKind.Announced));
    }

    [TestMethod]
    public async Task TransactionIdGetterReentryPreventsLengthReadAndTransactionPlan()
    {
        var stream = CreateHandshakeStream();
        var facts = new RecordingFactSink();
        var transactionId = Hash256.DoubleSha256("getter-reentry"u8);
        var source = new ReentrantTransactionIdSource(transactionId);
        await using var pump = CreatePump(
            stream,
            facts,
            new SingleSourceProvider(source),
            new BsvPeerStreamTransportOptions(leaveOpen: true));
        source.OnTransactionIdRead = () =>
            Assert.AreEqual(OperationStatus.InvalidData, pump.StartFetch(transactionId));
        Assert.AreEqual(OperationStatus.Done, pump.StartHandshake());
        await RunUntilAsync(
            pump,
            () => facts.HasHandshake(BsvHandshakeOutputKind.BecameReady) && !pump.HasLocalWork);
        Assert.AreEqual(OperationStatus.Done, pump.StartBroadcast(transactionId));
        await RunUntilAsync(
            pump,
            () => facts.HasBroadcast(BsvTransactionBroadcastOutputKind.Announced));
        stream.AppendInput(EncodeInventory("getdata"u8, transactionId));
        await RunUntilAsync(
            pump,
            () => facts.HasBroadcast(BsvTransactionBroadcastOutputKind.RequestedByPeer));
        var writtenBeforeGetter = stream.WrittenBytes.Count;
        var factsBeforeGetter = facts.BroadcastCount;

        var terminal = await RunUntilTerminalAsync(pump);

        Assert.AreEqual(BsvPeerTransportTerminalReason.DependencyReentry, terminal.Reason);
        Assert.AreEqual(0, source.LengthCallCount);
        Assert.AreEqual(1, source.DisposeCount);
        Assert.AreEqual(writtenBeforeGetter, stream.WrittenBytes.Count);
        Assert.AreEqual(factsBeforeGetter, facts.BroadcastCount);
        Assert.IsFalse(ReadCommands(stream.WrittenBytes).Contains("tx", StringComparer.Ordinal));
    }

    private static BsvPeerStreamTransportPump CreatePump(
        FakeDuplexStream stream,
        RecordingFactSink facts,
        IBsvTransactionPayloadSourceProvider sources,
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
            LocalNonce,
            "/Staffetta:transport-test/"u8,
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
            sources,
            facts,
            options);
    }

    private static FakeDuplexStream CreateHandshakeStream()
    {
        var frames = Concatenate(
            Concatenate(
                EncodeBasic("version"u8, CreateVersionPayload(PeerNonce)),
                EncodeBasic("verack"u8, [])),
            EncodeBasic("protoconf"u8, CreateProtoconfPayload()));
        return new FakeDuplexStream(frames, maximumReadLength: frames.Length);
    }

    private static async Task RunUntilAsync(
        BsvPeerStreamTransportPump pump,
        Func<bool> predicate,
        Action? afterStep = null,
        int maximumSteps = 20_000)
    {
        for (var step = 0; step < maximumSteps && !predicate(); step++)
        {
            var result = await pump.StepAsync();
            Assert.AreEqual(
                BsvPeerTransportStepKind.Progress,
                result.Kind,
                $"Unexpected terminal reason: {result.Reason}.");
            afterStep?.Invoke();
        }

        Assert.IsTrue(predicate(), "The transport did not reach the expected state.");
    }

    private static async Task<BsvPeerTransportStepResult> RunUntilTerminalAsync(
        BsvPeerStreamTransportPump pump,
        int maximumSteps = 20_000)
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

    private static byte[] CreateVersionPayload(
        ulong nonce,
        int protocolVersion = MinimumProtocolVersion)
    {
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [192, 0, 2, 10], 8333, out var receiving));
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [192, 0, 2, 11], 8333, out var source));
        var version = new VersionPayload(
            protocolVersion,
            services: 1,
            timestampUnixSeconds: 1_788_131_200,
            receiving,
            source,
            nonce,
            "/Staffetta:peer-test/"u8,
            startHeight: 948_321,
            relay: true);
        var payload = new byte[VersionPayloadCodec.MaximumPayloadLength];
        Assert.AreEqual(OperationStatus.Done, VersionPayloadCodec.TryWrite(payload, version, out var written));
        return payload[..written];
    }

    private static byte[] CreateProtoconfPayload()
    {
        var payload = new byte[ProtoconfPayloadCodec.MaximumStreamPoliciesLength + 8];
        Assert.AreEqual(
            OperationStatus.Done,
            ProtoconfPayloadCodec.TryWrite(
                payload,
                (uint)MaximumPayloadLength,
                "Default"u8,
                includeStreamPolicies: true,
                out var written));
        return payload[..written];
    }

    private static byte[] CreateNoncePayload(ulong nonce)
    {
        var payload = new byte[ModernPingPongPayloadCodec.EncodedLength];
        Assert.AreEqual(
            OperationStatus.Done,
            ModernPingPongPayloadCodec.TryWrite(payload, nonce, out var written));
        Assert.AreEqual(payload.Length, written);
        return payload;
    }

    private static byte[] EncodeInventory(ReadOnlySpan<byte> command, Hash256 transactionId)
    {
        var payload = new byte[1 + InventoryVectorCodec.EncodedLength];
        var vector = new[] { new InventoryVector(1, transactionId) };
        Assert.AreEqual(
            OperationStatus.Done,
            InventoryPayloadCodec.TryWrite(vector, payload, (ulong)payload.Length, out var written));
        Assert.AreEqual(payload.Length, written);
        return EncodeBasic(command, payload);
    }

    private static byte[] EncodeBasic(ReadOnlySpan<byte> command, ReadOnlySpan<byte> payload)
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

    private static byte[] Concatenate(byte[] first, byte[] second)
    {
        var result = new byte[first.Length + second.Length];
        first.CopyTo(result, 0);
        second.CopyTo(result, first.Length);
        return result;
    }

    private static string[] ReadCommands(IReadOnlyList<byte> wire)
    {
        var bytes = wire.ToArray();
        var commands = new List<string>();
        var offset = 0;
        Span<byte> command = stackalloc byte[MessageCommand.MaximumLength];
        while (offset != bytes.Length)
        {
            Assert.AreEqual(
                OperationStatus.Done,
                MessageHeaderCodec.TryParse(
                    bytes.AsSpan(offset),
                    NetworkMagic,
                    MaximumPayloadLength,
                    out var header,
                    out var headerLength));
            command.Clear();
            Assert.AreEqual(OperationStatus.Done, header.Command.TryCopyTo(command, out var commandLength));
            commands.Add(System.Text.Encoding.ASCII.GetString(command[..commandLength]));
            offset += checked(headerLength + (int)header.PayloadLength);
        }

        return commands.ToArray();
    }

    private static void AssertTransactionFrame(
        IReadOnlyList<byte> wire,
        Hash256 transactionId,
        byte[] expectedPayload)
    {
        var bytes = wire.ToArray();
        var offset = 0;
        var found = false;
        while (offset != bytes.Length)
        {
            Assert.AreEqual(
                OperationStatus.Done,
                MessageHeaderCodec.TryParse(
                    bytes.AsSpan(offset),
                    NetworkMagic,
                    MaximumPayloadLength,
                    out var header,
                    out var headerLength));
            var payloadLength = checked((int)header.PayloadLength);
            if (header.Command.Equals("tx"u8))
            {
                CollectionAssert.AreEqual(
                    expectedPayload,
                    bytes.AsSpan(offset + headerLength, payloadLength).ToArray());
                Assert.AreEqual(transactionId, Hash256.DoubleSha256(expectedPayload));
                found = true;
            }

            offset += headerLength + payloadLength;
        }

        Assert.IsTrue(found);
    }

    private sealed class FakeDuplexStream : Stream
    {
        private readonly List<byte> _input;
        private readonly int _maximumReadLength;
        private int _inputOffset;

        internal FakeDuplexStream(byte[] input, int maximumReadLength)
        {
            _input = new List<byte>(input);
            _maximumReadLength = maximumReadLength;
        }

        internal List<byte> WrittenBytes { get; } = [];

        internal int ReadCallCount { get; private set; }

        internal bool FailNextWriteAfterSideEffect { get; set; }

        internal Action? OnNextWrite { get; set; }

        internal int DisposeCount { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        internal void AppendInput(byte[] bytes) => _input.AddRange(bytes);

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReadCallCount++;
            if (_inputOffset == _input.Count)
            {
                return ValueTask.FromResult(0);
            }

            var length = Math.Min(
                Math.Min(buffer.Length, _maximumReadLength),
                _input.Count - _inputOffset);
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
            cancellationToken.ThrowIfCancellationRequested();
            WrittenBytes.AddRange(buffer.Span.ToArray());
            var onNextWrite = OnNextWrite;
            OnNextWrite = null;
            onNextWrite?.Invoke();
            if (FailNextWriteAfterSideEffect)
            {
                FailNextWriteAfterSideEffect = false;
                throw new IOException("Injected ambiguous write failure.");
            }

            return ValueTask.CompletedTask;
        }

        public override async ValueTask DisposeAsync()
        {
            DisposeCount++;
            await base.DisposeAsync();
        }

        public override void Flush() => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }

    private sealed class SingleSourceProvider(IBsvTransactionPayloadSource source) :
        IBsvTransactionPayloadSourceProvider
    {
        public ValueTask<IBsvTransactionPayloadSource?> OpenAsync(
            Hash256 transactionId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<IBsvTransactionPayloadSource?>(source);
        }
    }

    private sealed class MissingSourceProvider : IBsvTransactionPayloadSourceProvider
    {
        public ValueTask<IBsvTransactionPayloadSource?> OpenAsync(
            Hash256 transactionId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<IBsvTransactionPayloadSource?>(null);
        }
    }

    private sealed class BufferTransactionSource : IBsvTransactionPayloadSource
    {
        private readonly byte[] _payload;
        private readonly int _maximumReadLength;
        private readonly ulong _declaredLength;
        private int _offset;

        internal BufferTransactionSource(
            Hash256 transactionId,
            byte[] payload,
            ulong? declaredLength = null,
            int maximumReadLength = int.MaxValue)
        {
            TransactionId = transactionId;
            _payload = payload;
            _declaredLength = declaredLength ?? (ulong)payload.Length;
            _maximumReadLength = maximumReadLength;
        }

        public Hash256 TransactionId { get; }

        public ulong Length
        {
            get
            {
                LengthReadCount++;
                return LengthReadCount == 1 || LengthAfterFirstRead is null
                    ? _declaredLength
                    : LengthAfterFirstRead.Value;
            }
        }

        internal int LengthReadCount { get; private set; }

        internal ulong? LengthAfterFirstRead { get; init; }

        internal ulong BytesRead { get; private set; }

        internal int DisposeCount { get; private set; }

        internal Action? OnDispose { get; set; }

        public ValueTask<int> ReadAsync(
            Memory<byte> destination,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var length = Math.Min(
                Math.Min(destination.Length, _maximumReadLength),
                _payload.Length - _offset);
            _payload.AsSpan(_offset, length).CopyTo(destination.Span);
            _offset += length;
            BytesRead += (ulong)length;
            return ValueTask.FromResult(length);
        }

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            OnDispose?.Invoke();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ReentrantTransactionIdSource : IBsvTransactionPayloadSource
    {
        private readonly Hash256 _transactionId;

        internal ReentrantTransactionIdSource(Hash256 transactionId)
        {
            _transactionId = transactionId;
        }

        public Hash256 TransactionId
        {
            get
            {
                OnTransactionIdRead?.Invoke();
                return _transactionId;
            }
        }

        public ulong Length
        {
            get
            {
                LengthCallCount++;
                throw new InvalidOperationException("Length must not be read after getter reentry.");
            }
        }

        internal Action? OnTransactionIdRead { get; set; }

        internal int LengthCallCount { get; private set; }

        internal int DisposeCount { get; private set; }

        public ValueTask<int> ReadAsync(
            Memory<byte> destination,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No transaction payload may be read.");

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class RecordingFactSink : IBsvPeerSessionFactSink
    {
        private readonly List<BsvHandshakeOutput> _handshake = [];
        private readonly List<BsvTransactionBroadcastOutput> _broadcast = [];

        internal Action<BsvTransactionBroadcastOutput>? OnBroadcastFact { get; set; }

        internal int BroadcastCount => _broadcast.Count;

        internal bool HasHandshake(BsvHandshakeOutputKind kind) =>
            _handshake.Exists(output => output.Kind == kind);

        internal bool HasBroadcast(BsvTransactionBroadcastOutputKind kind) =>
            _broadcast.Exists(output => output.Kind == kind);

        public ValueTask OnHandshakeFactAsync(
            BsvHandshakeOutput output,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _handshake.Add(output);
            return ValueTask.CompletedTask;
        }

        public ValueTask OnBroadcastFactAsync(
            BsvTransactionBroadcastOutput output,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _broadcast.Add(output);
            OnBroadcastFact?.Invoke(output);
            return ValueTask.CompletedTask;
        }

        public ValueTask OnFetchFactAsync(
            BsvTransactionFetchOutput output,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class NoOpTransactionSink : ILegacyTransactionSink
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
}
