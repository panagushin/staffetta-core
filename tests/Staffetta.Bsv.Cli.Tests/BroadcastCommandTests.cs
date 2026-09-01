using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Relay;
using Staffetta.Core.Protocol.Transport;

namespace Staffetta.Bsv.Cli.Tests;

[TestClass]
public sealed class BroadcastCommandTests
{
    private static readonly string[] SuccessfulOutboundCommands =
        ["version", "verack", "protoconf", "inv", "tx"];

    private static readonly string[] SuccessfulEventTypes =
    [
        "broadcast.prepared",
        "connection.opened",
        "broadcast.queue",
        "handshake.ready",
        "broadcast.application",
        "broadcast.fact",
        "broadcast.fact",
        "broadcast.fact",
        "broadcast.fact",
        "broadcast.observation",
        "session.stopped",
    ];

    private static readonly string[] InventoryOnlyOutboundCommands =
        ["version", "verack", "protoconf", "inv"];

    [TestMethod]
    public async Task ScriptedPeerRequestsTransactionAndRelaysItBackWithExactWireBytes()
    {
        var path = await TransactionFixture.WriteTempAsync(180_000);
        try
        {
            var expected = await File.ReadAllBytesAsync(path);
            await using var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None);
            var connection = new FakePeerConnection(PeerFrames.Ready());
            var output = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
            var application = new BsvReferenceCliApplication(
                new FakePeerConnector(connection),
                new TestRuntime(),
                output,
                new StringWriter());

            var running = application.RunBroadcastAsync(
                CreateArguments(path),
                prepared,
                CancellationToken.None).AsTask();
            await WaitUntilAsync(() => HasOutboundCommand(connection, "inv"));
            connection.PeerStream.AppendInput(PeerFrames.Inventory("getdata", prepared.TransactionId));
            await WaitUntilAsync(() => HasOutboundCommand(connection, "tx"));
            connection.PeerStream.AppendInput(PeerFrames.Inventory("inv", prepared.TransactionId));
            var exit = await running;

            Assert.AreEqual(CliExitCode.Success, exit);
            CollectionAssert.AreEqual(
                SuccessfulOutboundCommands,
                PeerFrames.ReadOutboundCommands(connection.PeerStream.WrittenBytes));
            CollectionAssert.AreEqual(
                expected,
                PeerFrames.ReadOutboundPayload(connection.PeerStream.WrittenBytes, "tx"));
            Assert.IsLessThanOrEqualTo(prepared.MaximumReadRequestLength, PreparedBinaryTransaction.BufferLength);
            CollectionAssert.AreEqual(
                SuccessfulEventTypes,
                ReadTypes(output));
            var facts = ReadFacts(output);
            CollectionAssert.AreEqual(
                new[]
                {
                    BsvTransactionBroadcastOutputKind.Announced.ToString(),
                    BsvTransactionBroadcastOutputKind.RequestedByPeer.ToString(),
                    BsvTransactionBroadcastOutputKind.SentToPeer.ToString(),
                    BsvTransactionBroadcastOutputKind.ObservedFromPeer.ToString(),
                },
                facts);
            StringAssert.Contains(output.ToString(), "\"willBroadcast\":true");
            Assert.AreEqual(1, connection.AbortCount);
            Assert.AreEqual(1, connection.DisposeCount);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task PeerRejectAfterTransactionCommitIsReportedWithoutSuccess()
    {
        var path = await TransactionFixture.WriteTempAsync();
        try
        {
            await using var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None);
            var connection = new FakePeerConnection(PeerFrames.Ready());
            var output = new StringWriter();
            var application = new BsvReferenceCliApplication(
                new FakePeerConnector(connection),
                new TestRuntime(),
                output,
                new StringWriter());

            var running = application.RunBroadcastAsync(
                CreateArguments(path),
                prepared,
                CancellationToken.None).AsTask();
            await WaitUntilAsync(() => HasOutboundCommand(connection, "inv"));
            connection.PeerStream.AppendInput(PeerFrames.Inventory("getdata", prepared.TransactionId));
            await WaitUntilAsync(() => HasOutboundCommand(connection, "tx"));
            connection.PeerStream.AppendInput(PeerFrames.TransactionReject(prepared.TransactionId));
            var exit = await running;

            Assert.AreEqual(CliExitCode.PeerSessionFailure, exit);
            CollectionAssert.Contains(ReadFacts(output), BsvTransactionBroadcastOutputKind.SentToPeer.ToString());
            CollectionAssert.Contains(ReadFacts(output), BsvTransactionBroadcastOutputKind.Rejected.ToString());
            var lines = Lines(output);
            StringAssert.Contains(lines[^1], "\"stage\":\"broadcast\"");
            StringAssert.Contains(lines[^1], "\"reason\":\"peer_reject\"");
            Assert.IsFalse(lines.Any(static line => line.Contains("session.stopped", StringComparison.Ordinal)));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task NoGetDataTimesOutAfterCommittedInventoryWithoutSendingTransaction()
    {
        var path = await TransactionFixture.WriteTempAsync();
        try
        {
            await using var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None);
            var connection = new FakePeerConnection(PeerFrames.Ready());
            var output = new StringWriter();
            var deliveryDeadline = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var application = new BsvReferenceCliApplication(
                new FakePeerConnector(connection),
                new TestRuntime(TestRuntime.Infinite, TestRuntime.Infinite, _ => deliveryDeadline.Task),
                output,
                new StringWriter());

            var running = application.RunBroadcastAsync(
                CreateArguments(path),
                prepared,
                CancellationToken.None).AsTask();
            await WaitUntilAsync(() => output.ToString().Contains("\"fact\":\"Announced\"", StringComparison.Ordinal));
            deliveryDeadline.SetResult();
            var exit = await running;

            Assert.AreEqual(CliExitCode.Timeout, exit);
            CollectionAssert.AreEqual(
                InventoryOnlyOutboundCommands,
                PeerFrames.ReadOutboundCommands(connection.PeerStream.WrittenBytes));
            CollectionAssert.AreEqual(
                new[] { BsvTransactionBroadcastOutputKind.Announced.ToString() },
                ReadFacts(output));
            StringAssert.Contains(Lines(output)[^1], "\"kind\":\"timeout\"");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task EarlyPeerInventoryWithoutGetDataDoesNotClaimDeliverySuccess()
    {
        var path = await TransactionFixture.WriteTempAsync();
        try
        {
            await using var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None);
            var connection = new FakePeerConnection(PeerFrames.Ready());
            var output = new StringWriter();
            var deliveryDeadline = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var application = new BsvReferenceCliApplication(
                new FakePeerConnector(connection),
                new TestRuntime(TestRuntime.Infinite, TestRuntime.Infinite, _ => deliveryDeadline.Task),
                output,
                new StringWriter());

            var running = application.RunBroadcastAsync(CreateArguments(path), prepared, CancellationToken.None).AsTask();
            await WaitUntilAsync(() => HasOutboundCommand(connection, "inv"));
            connection.PeerStream.AppendInput(PeerFrames.Inventory("inv", prepared.TransactionId));
            await WaitUntilAsync(() => output.ToString().Contains("ObservedFromPeer", StringComparison.Ordinal));
            deliveryDeadline.SetResult();
            var exit = await running;

            Assert.AreEqual(CliExitCode.Timeout, exit);
            CollectionAssert.Contains(
                ReadFacts(output),
                BsvTransactionBroadcastOutputKind.ObservedFromPeer.ToString());
            CollectionAssert.DoesNotContain(
                ReadFacts(output),
                BsvTransactionBroadcastOutputKind.SentToPeer.ToString());
            StringAssert.Contains(Lines(output)[^1], "\"kind\":\"timeout\"");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task SentWithoutRelayBackSucceedsAfterBoundedObservationWindow()
    {
        var path = await TransactionFixture.WriteTempAsync();
        try
        {
            await using var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None);
            var connection = new FakePeerConnection(PeerFrames.Ready());
            var output = new StringWriter();
            var application = new BsvReferenceCliApplication(
                new FakePeerConnector(connection),
                new TestRuntime(
                    TestRuntime.Infinite,
                    TestRuntime.Infinite,
                    TestRuntime.Infinite,
                    TestRuntime.Immediate),
                output,
                new StringWriter());

            var running = application.RunBroadcastAsync(CreateArguments(path), prepared, CancellationToken.None).AsTask();
            await WaitUntilAsync(() => HasOutboundCommand(connection, "inv"));
            connection.PeerStream.AppendInput(PeerFrames.Inventory("getdata", prepared.TransactionId));
            var exit = await running;

            Assert.AreEqual(CliExitCode.Success, exit);
            CollectionAssert.Contains(ReadFacts(output), BsvTransactionBroadcastOutputKind.SentToPeer.ToString());
            StringAssert.Contains(output.ToString(), "\"outcome\":\"not_observed\"");
            StringAssert.Contains(Lines(output)[^1], "\"reason\":\"sent_not_observed\"");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task InvalidTransactionNeverConstructsConnectorForBroadcast()
    {
        var path = Path.Combine(Path.GetTempPath(), $"staffetta-cli-{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(path, [1, 2, 3]);
        try
        {
            Assert.IsTrue(CliArguments.TryParse(
                ["broadcast", "--peer", "node.example:8333", "--tx-file", path],
                out var arguments,
                out _,
                out var error), error);
            var connectorCalls = 0;
            var exit = await ReferenceCliDispatcher.RunAsync(
                arguments!,
                () =>
                {
                    connectorCalls++;
                    throw new AssertFailedException("network capability constructed");
                },
                new TestRuntime(),
                new StringWriter(),
                new StringWriter(),
                CancellationToken.None);

            Assert.AreEqual(CliExitCode.TransactionInput, exit);
            Assert.AreEqual(0, connectorCalls);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task PartialPostHandshakeFrameCannotStrandCommandApplication()
    {
        var path = await TransactionFixture.WriteTempAsync();
        try
        {
            await using var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None);
            var connection = new FakePeerConnection(PeerFrames.ReadyThen([0xe3]));
            var output = new StringWriter();
            var application = new BsvReferenceCliApplication(
                new FakePeerConnector(connection),
                new TestRuntime(TestRuntime.Infinite, TestRuntime.Infinite, TestRuntime.Immediate),
                output,
                new StringWriter());

            var exit = await application.RunBroadcastAsync(
                CreateArguments(path),
                prepared,
                CancellationToken.None);

            Assert.AreEqual(CliExitCode.Timeout, exit);
            CollectionAssert.DoesNotContain(
                PeerFrames.ReadOutboundCommands(connection.PeerStream.WrittenBytes),
                "inv");
            StringAssert.Contains(output.ToString(), "\"kind\":\"Stopped\"");
            StringAssert.Contains(Lines(output)[^1], "deadline_exceeded_before_application");
            Assert.AreEqual(1, connection.AbortCount);
            Assert.AreEqual(1, connection.DisposeCount);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task SlowApplicationEvidenceCannotEscapeDeliveryDeadlineOrSkipQuiescence()
    {
        var path = await TransactionFixture.WriteTempAsync();
        try
        {
            await using var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None);
            var connection = new FakePeerConnection(PeerFrames.Ready());
            var deliveryDeadline = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var output = new BlockingOnContentWriter("broadcast.application");
            var application = new BsvReferenceCliApplication(
                new FakePeerConnector(connection),
                new TestRuntime(TestRuntime.Infinite, TestRuntime.Infinite, _ => deliveryDeadline.Task),
                output,
                new StringWriter());

            var running = application.RunBroadcastAsync(CreateArguments(path), prepared, CancellationToken.None).AsTask();
            await output.Blocked;
            deliveryDeadline.SetResult();
            output.Release();
            var exit = await running;

            Assert.AreEqual(CliExitCode.Timeout, exit);
            StringAssert.Contains(output.ToString(), "broadcast.application");
            StringAssert.Contains(Lines(output)[^1], "deadline_exceeded_before_application");
            Assert.AreEqual(1, connection.AbortCount);
            Assert.AreEqual(1, connection.DisposeCount);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    [DataRow(false, "TransactionHashMismatch")]
    [DataRow(true, "TransactionSourceFailure")]
    public async Task SourceAndHashFailuresNeverPublishSentFact(bool throwOnRead, string expectedReason)
    {
        var path = await TransactionFixture.WriteTempAsync();
        try
        {
            await using var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None);
            var source = new FaultableSource(
                prepared.TransactionId,
                new byte[checked((int)prepared.Length)],
                throwOnRead);
            var connection = new FakePeerConnection(PeerFrames.Ready());
            var output = new StringWriter();
            var application = new BsvReferenceCliApplication(
                new FakePeerConnector(connection),
                new TestRuntime(),
                output,
                new StringWriter());

            var running = application.RunBroadcastAsync(
                CreateArguments(path),
                prepared.Summary,
                new SingleSourceProvider(source),
                CancellationToken.None).AsTask();
            await WaitUntilAsync(() => HasOutboundCommand(connection, "inv"));
            connection.PeerStream.AppendInput(PeerFrames.Inventory("getdata", prepared.TransactionId));
            var exit = await running;

            Assert.AreEqual(CliExitCode.PeerSessionFailure, exit);
            CollectionAssert.DoesNotContain(
                ReadFacts(output),
                BsvTransactionBroadcastOutputKind.SentToPeer.ToString());
            StringAssert.Contains(Lines(output)[^1], expectedReason);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task StdoutFailureDuringCommittedFactCannotFabricateBroadcastSuccess()
    {
        var path = await TransactionFixture.WriteTempAsync();
        try
        {
            await using var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None);
            var connection = new FakePeerConnection(PeerFrames.Ready());
            var output = new ThrowAfterLinesWriter(5);
            var application = new BsvReferenceCliApplication(
                new FakePeerConnector(connection),
                new TestRuntime(),
                output,
                new StringWriter());

            var exit = await application.RunBroadcastAsync(
                CreateArguments(path),
                prepared,
                CancellationToken.None);

            Assert.AreEqual(CliExitCode.InternalError, exit);
            Assert.AreEqual(5, output.CompletedLineCount);
            Assert.IsFalse(output.ToString().Contains("session.stopped", StringComparison.Ordinal));
            Assert.AreEqual(1, connection.AbortCount);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task SocketFailureWhileWritingTransactionNeverPublishesSentFact()
    {
        var path = await TransactionFixture.WriteTempAsync();
        try
        {
            await using var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None);
            var connection = new FakePeerConnection(PeerFrames.Ready());
            var output = new StringWriter();
            var application = new BsvReferenceCliApplication(
                new FakePeerConnector(connection),
                new TestRuntime(),
                output,
                new StringWriter());

            var running = application.RunBroadcastAsync(
                CreateArguments(path),
                prepared,
                CancellationToken.None).AsTask();
            await WaitUntilAsync(() => HasOutboundCommand(connection, "inv"));
            connection.PeerStream.FailNextWrite();
            connection.PeerStream.AppendInput(PeerFrames.Inventory("getdata", prepared.TransactionId));
            var exit = await running;

            Assert.AreEqual(CliExitCode.PeerSessionFailure, exit);
            CollectionAssert.DoesNotContain(
                ReadFacts(output),
                BsvTransactionBroadcastOutputKind.SentToPeer.ToString());
            StringAssert.Contains(Lines(output)[^1], "TransportWriteFailure");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task PostSentFactOutputFailureIsInternalAndNeverFabricatesSuccess()
    {
        var path = await TransactionFixture.WriteTempAsync();
        try
        {
            await using var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None);
            var connection = new FakePeerConnection(PeerFrames.Ready());
            var output = new ThrowOnceOnContentWriter("ObservedFromPeer");
            var application = new BsvReferenceCliApplication(
                new FakePeerConnector(connection),
                new TestRuntime(),
                output,
                new StringWriter());

            var running = application.RunBroadcastAsync(CreateArguments(path), prepared, CancellationToken.None).AsTask();
            await WaitUntilAsync(() => HasOutboundCommand(connection, "inv"));
            connection.PeerStream.AppendInput(PeerFrames.Inventory("getdata", prepared.TransactionId));
            await WaitUntilAsync(() => output.ToString().Contains("SentToPeer", StringComparison.Ordinal));
            connection.PeerStream.AppendInput(PeerFrames.Inventory("inv", prepared.TransactionId));
            var exit = await running;

            Assert.AreEqual(CliExitCode.InternalError, exit);
            StringAssert.Contains(Lines(output)[^1], "FactSinkFailure");
            Assert.IsFalse(output.ToString().Contains("session.stopped", StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task RejectCommittedWhileObservationIsWrittenWinsOverSentSuccess()
    {
        var path = await TransactionFixture.WriteTempAsync();
        try
        {
            await using var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None);
            var connection = new FakePeerConnection(PeerFrames.Ready());
            var observationDeadline = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var output = new BlockingOnContentWriter("\"fact\":\"Rejected\"");
            var application = new BsvReferenceCliApplication(
                new FakePeerConnector(connection),
                new TestRuntime(
                    TestRuntime.Infinite,
                    TestRuntime.Infinite,
                    TestRuntime.Infinite,
                    _ => observationDeadline.Task),
                output,
                new StringWriter());

            var running = application.RunBroadcastAsync(CreateArguments(path), prepared, CancellationToken.None).AsTask();
            await WaitUntilAsync(() => HasOutboundCommand(connection, "inv"));
            connection.PeerStream.AppendInput(PeerFrames.Inventory("getdata", prepared.TransactionId));
            await WaitUntilAsync(() =>
                output.ToString().Contains("SentToPeer", StringComparison.Ordinal) &&
                connection.PeerStream.IsReadPending);
            connection.PeerStream.AppendInput(PeerFrames.TransactionReject(prepared.TransactionId));
            await output.Blocked;
            observationDeadline.SetResult();
            output.Release();
            var exit = await running;

            Assert.AreEqual(CliExitCode.PeerSessionFailure, exit);
            CollectionAssert.Contains(ReadFacts(output), BsvTransactionBroadcastOutputKind.Rejected.ToString());
            Assert.IsFalse(output.ToString().Contains("session.stopped", StringComparison.Ordinal));
            StringAssert.Contains(Lines(output)[^1], "peer_reject");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task NdjsonWriterSerializesSequenceAndWholeWritesAcrossCallers()
    {
        var output = new ConcurrencyDetectingWriter();
        var events = new NdjsonEventWriter(output);

        await Task.WhenAll(Enumerable.Range(0, 32)
            .Select(index => events.WriteConnectionOpenedAsync($"requested-{index}", $"remote-{index}").AsTask()));

        Assert.AreEqual(1, output.MaximumConcurrentWrites);
        var sequences = output.ToString()
            .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
            .Select(static line =>
            {
                using var document = JsonDocument.Parse(line);
                return document.RootElement.GetProperty("sequence").GetInt64();
            })
            .ToArray();
        CollectionAssert.AreEqual(Enumerable.Range(1, 32).Select(static value => (long)value).ToArray(), sequences);
    }

    [TestMethod]
    public async Task SentCommittedDuringDeadlineQuiescenceStillReturnsDeliverySuccess()
    {
        var path = await TransactionFixture.WriteTempAsync();
        try
        {
            await using var prepared = await PreparedBinaryTransaction.OpenAndValidateAsync(path, CancellationToken.None);
            var connection = new FakePeerConnection(PeerFrames.Ready());
            var deliveryDeadline = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var output = new BlockingOnContentWriter("SentToPeer");
            var application = new BsvReferenceCliApplication(
                new FakePeerConnector(connection),
                new TestRuntime(TestRuntime.Infinite, TestRuntime.Infinite, _ => deliveryDeadline.Task),
                output,
                new StringWriter());

            var running = application.RunBroadcastAsync(CreateArguments(path), prepared, CancellationToken.None).AsTask();
            await WaitUntilAsync(() => HasOutboundCommand(connection, "inv"));
            connection.PeerStream.AppendInput(PeerFrames.Inventory("getdata", prepared.TransactionId));
            await output.Blocked;
            deliveryDeadline.SetResult();
            output.Release();
            var exit = await running;

            Assert.AreEqual(CliExitCode.Success, exit);
            CollectionAssert.Contains(ReadFacts(output), BsvTransactionBroadcastOutputKind.SentToPeer.ToString());
            StringAssert.Contains(output.ToString(), "deadline_raced_with_send");
            StringAssert.Contains(Lines(output)[^1], "session.stopped");
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static CliArguments CreateArguments(string path) =>
        new(
            ReferenceCliCommand.Broadcast,
            new PeerEndpoint("node.example", 8333),
            path,
            TimeSpan.FromSeconds(5),
            TimeSpan.FromSeconds(30),
            TimeSpan.FromSeconds(30));

    private static string[] ReadTypes(StringWriter output) =>
        Lines(output).Select(static line =>
        {
            using var document = JsonDocument.Parse(line);
            return document.RootElement.GetProperty("type").GetString()!;
        }).ToArray();

    private static string[] ReadFacts(StringWriter output) =>
        Lines(output).Select(static line => JsonDocument.Parse(line))
            .Where(static document => document.RootElement.GetProperty("type").GetString() == "broadcast.fact")
            .Select(static document =>
            {
                using (document)
                {
                    return document.RootElement.GetProperty("fact").GetString()!;
                }
            })
            .ToArray();

    private static string[] Lines(StringWriter output) =>
        output.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);

    private static bool HasOutboundCommand(FakePeerConnection connection, string command)
    {
        try
        {
            return PeerFrames.ReadOutboundCommands(connection.PeerStream.WrittenBytes)
                .Contains(command, StringComparer.Ordinal);
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var attempt = 0; attempt < 1_000; attempt++)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(1);
        }

        Assert.Fail("Condition was not reached.");
    }

    private sealed class SingleSourceProvider(IBsvTransactionPayloadSource source) :
        IBsvTransactionPayloadSourceProvider
    {
        public ValueTask<IBsvTransactionPayloadSource?> OpenAsync(
            Hash256 transactionId,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult<IBsvTransactionPayloadSource?>(source);
    }

    private sealed class FaultableSource(
        Hash256 transactionId,
        byte[] payload,
        bool throwOnRead) : IBsvTransactionPayloadSource
    {
        private int _offset;

        public Hash256 TransactionId { get; } = transactionId;

        public ulong Length => (ulong)payload.Length;

        public ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (throwOnRead)
            {
                return ValueTask.FromException<int>(new IOException("source failed"));
            }

            var count = Math.Min(destination.Length, payload.Length - _offset);
            payload.AsMemory(_offset, count).CopyTo(destination);
            _offset += count;
            return ValueTask.FromResult(count);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class ThrowAfterLinesWriter(int allowedLines) : StringWriter
    {
        internal int CompletedLineCount { get; private set; }

        public override Task WriteLineAsync(
            ReadOnlyMemory<char> buffer,
            CancellationToken cancellationToken = default)
        {
            if (CompletedLineCount >= allowedLines)
            {
                throw new IOException("stdout failed");
            }

            CompletedLineCount++;
            return base.WriteLineAsync(buffer, cancellationToken);
        }
    }

    private sealed class ThrowOnceOnContentWriter(string content) : StringWriter
    {
        private int _thrown;

        public override Task WriteLineAsync(
            ReadOnlyMemory<char> buffer,
            CancellationToken cancellationToken = default)
        {
            if (buffer.Span.Contains(content, StringComparison.Ordinal) &&
                Interlocked.Exchange(ref _thrown, 1) == 0)
            {
                throw new IOException("one-shot stdout failure");
            }

            return base.WriteLineAsync(buffer, cancellationToken);
        }
    }

    private sealed class ConcurrencyDetectingWriter : StringWriter
    {
        private int _concurrent;
        private int _maximumConcurrent;

        internal int MaximumConcurrentWrites => Volatile.Read(ref _maximumConcurrent);

        public override async Task WriteLineAsync(
            ReadOnlyMemory<char> buffer,
            CancellationToken cancellationToken = default)
        {
            var concurrent = Interlocked.Increment(ref _concurrent);
            InterlockedExtensions.Max(ref _maximumConcurrent, concurrent);
            try
            {
                await Task.Yield();
                await base.WriteLineAsync(buffer, cancellationToken);
            }
            finally
            {
                Interlocked.Decrement(ref _concurrent);
            }
        }
    }

    private sealed class BlockingOnContentWriter(string content) : StringWriter
    {
        private readonly TaskCompletionSource _blocked =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal Task Blocked => _blocked.Task;

        internal void Release() => _release.TrySetResult();

        public override async Task WriteLineAsync(
            ReadOnlyMemory<char> buffer,
            CancellationToken cancellationToken = default)
        {
            await base.WriteLineAsync(buffer, cancellationToken);
            if (buffer.Span.Contains(content, StringComparison.Ordinal))
            {
                _blocked.TrySetResult();
                await _release.Task.ConfigureAwait(false);
            }
        }
    }

    private static class InterlockedExtensions
    {
        internal static void Max(ref int location, int value)
        {
            var current = Volatile.Read(ref location);
            while (current < value)
            {
                var observed = Interlocked.CompareExchange(ref location, value, current);
                if (observed == current)
                {
                    return;
                }

                current = observed;
            }
        }
    }
}
