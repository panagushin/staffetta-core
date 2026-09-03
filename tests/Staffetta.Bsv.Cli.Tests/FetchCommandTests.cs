using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Messages;
using Staffetta.Core.Protocol.Relay;

namespace Staffetta.Bsv.Cli.Tests;

[TestClass]
public sealed class FetchCommandTests
{
    private static readonly string[] SuccessfulOutboundCommands =
        ["version", "verack", "protoconf", "getdata"];

    private static readonly string[] SuccessfulEventTypes =
    [
        "connection.opened",
        "fetch.queue",
        "handshake.ready",
        "fetch.application",
        "fetch.fact",
        "fetch.fact",
        "fetch.terminal",
        "session.stopped",
    ];

    [TestMethod]
    public async Task InventoryCommitsGetDataAndValidatedTransactionIsTheOnlySuccess()
    {
        var transaction = TransactionFixture.CreateMinimal();
        var transactionId = Hash256.DoubleSha256(transaction);
        var connection = new FakePeerConnection(PeerFrames.Ready());
        var output = new ThreadSafeStringWriter();

        var running = ReferenceCliDispatcher.RunAsync(
                CreateArguments(transactionId),
                () => new FakePeerConnector(connection),
                new TestRuntime(),
                output,
                new ThreadSafeStringWriter(),
                CancellationToken.None)
            .AsTask();
        await WaitUntilAsync(() => output.ToString().Contains("handshake.ready", StringComparison.Ordinal));
        connection.PeerStream.AppendInput(PeerFrames.Inventory("inv", transactionId));
        await WaitUntilAsync(() => HasOutboundCommand(connection, "getdata"));
        connection.PeerStream.AppendInput(PeerFrames.Transaction(transaction));

        var exit = await running.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreEqual(CliExitCode.Success, exit);
        CollectionAssert.AreEqual(
            SuccessfulOutboundCommands,
            PeerFrames.ReadOutboundCommands(connection.PeerStream.WrittenBytes));
        var versionBytes = PeerFrames.ReadOutboundPayload(connection.PeerStream.WrittenBytes, "version");
        Assert.AreEqual(
            System.Buffers.OperationStatus.Done,
            VersionPayloadCodec.TryParse(versionBytes, out var version, out var versionLength));
        Assert.AreEqual(versionBytes.Length, versionLength);
        Assert.IsTrue(version.HasRelay);
        Assert.IsTrue(version.Relay);
        CollectionAssert.AreEqual(
            CreateInventoryPayload(transactionId),
            PeerFrames.ReadOutboundPayload(connection.PeerStream.WrittenBytes, "getdata"));
        CollectionAssert.AreEqual(
            SuccessfulEventTypes,
            ReadTypes(output));
        CollectionAssert.AreEqual(
            new[]
            {
                BsvTransactionFetchOutputKind.Requested.ToString(),
                BsvTransactionFetchOutputKind.Received.ToString(),
            },
            ReadFacts(output));
        StringAssert.Contains(Lines(output)[^2], "\"outcome\":\"received\"");
        StringAssert.Contains(Lines(output)[^2], transactionId.ToDisplayHex());
        Assert.AreEqual(1, connection.AbortCount);
        Assert.AreEqual(1, connection.DisposeCount);
    }

    [TestMethod]
    public async Task NotFoundAfterCommittedGetDataIsNotReceipt()
    {
        var transactionId = Hash256.DoubleSha256(TransactionFixture.CreateMinimal());
        var connection = new FakePeerConnection(PeerFrames.Ready());
        var output = new ThreadSafeStringWriter();
        var application = CreateApplication(connection, output, new TestRuntime());

        var running = application.RunAsync(CreateArguments(transactionId), CancellationToken.None).AsTask();
        await WaitUntilAsync(() => output.ToString().Contains("handshake.ready", StringComparison.Ordinal));
        connection.PeerStream.AppendInput(PeerFrames.Inventory("inv", transactionId));
        await WaitUntilAsync(() => HasOutboundCommand(connection, "getdata"));
        connection.PeerStream.AppendInput(PeerFrames.Inventory("notfound", transactionId));

        var exit = await running.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreEqual(CliExitCode.PeerSessionFailure, exit);
        CollectionAssert.AreEqual(
            new[]
            {
                BsvTransactionFetchOutputKind.Requested.ToString(),
                BsvTransactionFetchOutputKind.NotFound.ToString(),
            },
            ReadFacts(output));
        Assert.IsFalse(output.ToString().Contains("\"fact\":\"Received\"", StringComparison.Ordinal));
        StringAssert.Contains(Lines(output)[^1], "\"outcome\":\"not_found\"");
    }

    [TestMethod]
    public async Task InventoryAloneTimesOutWithoutClaimingReceipt()
    {
        var transactionId = Hash256.DoubleSha256(TransactionFixture.CreateMinimal());
        var connection = new FakePeerConnection(PeerFrames.Ready());
        var deadline = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var output = new ThreadSafeStringWriter();
        var application = CreateApplication(
            connection,
            output,
            new TestRuntime(TestRuntime.Infinite, TestRuntime.Infinite, _ => deadline.Task));

        var running = application.RunAsync(CreateArguments(transactionId), CancellationToken.None).AsTask();
        await WaitUntilAsync(() => output.ToString().Contains("handshake.ready", StringComparison.Ordinal));
        connection.PeerStream.AppendInput(PeerFrames.Inventory("inv", transactionId));
        await WaitUntilAsync(() => output.ToString().Contains("\"fact\":\"Requested\"", StringComparison.Ordinal));
        deadline.SetResult();

        var exit = await running.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreEqual(CliExitCode.Timeout, exit);
        CollectionAssert.AreEqual(
            new[] { BsvTransactionFetchOutputKind.Requested.ToString() },
            ReadFacts(output));
        StringAssert.Contains(Lines(output)[^1], "\"outcome\":\"timeout\"");
        Assert.IsFalse(output.ToString().Contains("\"outcome\":\"received\"", StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task UnsolicitedTargetTransactionCannotBypassInventoryAndGetData()
    {
        var transaction = TransactionFixture.CreateMinimal();
        var transactionId = Hash256.DoubleSha256(transaction);
        var connection = new FakePeerConnection(PeerFrames.Ready());
        var output = new ThreadSafeStringWriter();
        var application = CreateApplication(connection, output, new TestRuntime());

        var running = application.RunAsync(CreateArguments(transactionId), CancellationToken.None).AsTask();
        await WaitUntilAsync(() => output.ToString().Contains("fetch.application", StringComparison.Ordinal));
        connection.PeerStream.AppendInput(PeerFrames.Transaction(transaction));

        var exit = await running.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreEqual(CliExitCode.PeerSessionFailure, exit);
        CollectionAssert.DoesNotContain(
            PeerFrames.ReadOutboundCommands(connection.PeerStream.WrittenBytes),
            "getdata");
        CollectionAssert.Contains(ReadFacts(output), BsvTransactionFetchOutputKind.Received.ToString());
        StringAssert.Contains(Lines(output)[^1], "received_before_request_commit");
        Assert.IsFalse(output.ToString().Contains("session.stopped", StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task ReceiptCommittedDuringDeadlineQuiescenceIsNotMisclassifiedAsTimeout()
    {
        var transaction = TransactionFixture.CreateMinimal();
        var transactionId = Hash256.DoubleSha256(transaction);
        var connection = new FakePeerConnection(PeerFrames.Ready());
        var deadline = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var output = new BlockingOnContentWriter("\"fact\":\"Received\"");
        var application = CreateApplication(
            connection,
            output,
            new TestRuntime(TestRuntime.Infinite, TestRuntime.Infinite, _ => deadline.Task));

        var running = application.RunAsync(CreateArguments(transactionId), CancellationToken.None).AsTask();
        try
        {
            await WaitUntilAsync(() => output.ToString().Contains("fetch.application", StringComparison.Ordinal));
            connection.PeerStream.AppendInput(PeerFrames.Transaction(transaction));
            // Appending input does not prove receipt. Hold delivery of the committed Received fact
            // so the deadline must quiesce the actor before classifying its final outcome.
            await output.Blocked.WaitAsync(TimeSpan.FromSeconds(5));
            deadline.SetResult();
            await WaitUntilAsync(() => connection.AbortCount == 1);
            Assert.IsFalse(running.IsCompleted);
            Assert.IsFalse(output.ToString().Contains("fetch.terminal", StringComparison.Ordinal));
        }
        finally
        {
            deadline.TrySetResult();
            output.Release();
        }

        var exit = await running.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreEqual(CliExitCode.PeerSessionFailure, exit);
        CollectionAssert.Contains(ReadFacts(output), BsvTransactionFetchOutputKind.Received.ToString());
        StringAssert.Contains(Lines(output)[^1], "received_before_request_commit");
        Assert.IsFalse(output.ToString().Contains("\"outcome\":\"timeout\"", StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task ApplicationDeadlineBeforeAnyReceiptCommitsRemainsTimeout()
    {
        var transactionId = Hash256.DoubleSha256(TransactionFixture.CreateMinimal());
        var connection = new FakePeerConnection(PeerFrames.Ready());
        var deadline = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var output = new BlockingOnContentWriter("fetch.application");
        var application = CreateApplication(
            connection,
            output,
            new TestRuntime(TestRuntime.Infinite, TestRuntime.Infinite, _ => deadline.Task));

        var running = application.RunAsync(CreateArguments(transactionId), CancellationToken.None).AsTask();
        try
        {
            await output.Blocked.WaitAsync(TimeSpan.FromSeconds(5));
            deadline.SetResult();
            await WaitUntilAsync(() => connection.AbortCount == 1);
            Assert.IsFalse(running.IsCompleted);
            Assert.IsFalse(output.ToString().Contains("fetch.terminal", StringComparison.Ordinal));
        }
        finally
        {
            deadline.TrySetResult();
            output.Release();
        }

        var exit = await running.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreEqual(CliExitCode.Timeout, exit);
        Assert.IsEmpty(ReadFacts(output));
        StringAssert.Contains(Lines(output)[^1], "\"outcome\":\"timeout\"");
        StringAssert.Contains(Lines(output)[^1], "deadline_exceeded_before_application");
        Assert.AreEqual(1, connection.AbortCount);
        Assert.AreEqual(1, connection.DisposeCount);
    }

    [TestMethod]
    public async Task NotFoundCommittedDuringDeadlineQuiescenceWinsOverTimeout()
    {
        var transactionId = Hash256.DoubleSha256(TransactionFixture.CreateMinimal());
        var connection = new FakePeerConnection(PeerFrames.Ready());
        var deadline = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var output = new BlockingOnContentWriter("\"fact\":\"NotFound\"");
        var application = CreateApplication(
            connection,
            output,
            new TestRuntime(TestRuntime.Infinite, TestRuntime.Infinite, _ => deadline.Task));

        var running = application.RunAsync(CreateArguments(transactionId), CancellationToken.None).AsTask();
        await WaitUntilAsync(() => output.ToString().Contains("handshake.ready", StringComparison.Ordinal));
        connection.PeerStream.AppendInput(PeerFrames.Inventory("inv", transactionId));
        await WaitUntilAsync(() => output.ToString().Contains("\"fact\":\"Requested\"", StringComparison.Ordinal));
        connection.PeerStream.AppendInput(PeerFrames.Inventory("notfound", transactionId));
        try
        {
            await output.Blocked.WaitAsync(TimeSpan.FromSeconds(5));
            deadline.SetResult();
            await WaitUntilAsync(() => connection.AbortCount == 1);
        }
        finally
        {
            deadline.TrySetResult();
            output.Release();
        }

        var exit = await running.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreEqual(CliExitCode.PeerSessionFailure, exit);
        CollectionAssert.Contains(ReadFacts(output), BsvTransactionFetchOutputKind.NotFound.ToString());
        StringAssert.Contains(Lines(output)[^1], "\"outcome\":\"not_found\"");
        Assert.IsFalse(output.ToString().Contains("\"outcome\":\"timeout\"", StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task DisconnectAfterRequestIsATransportTerminalNotReceipt()
    {
        var transactionId = Hash256.DoubleSha256(TransactionFixture.CreateMinimal());
        var connection = new FakePeerConnection(PeerFrames.Ready());
        var output = new ThreadSafeStringWriter();
        var application = CreateApplication(connection, output, new TestRuntime());

        var running = application.RunAsync(CreateArguments(transactionId), CancellationToken.None).AsTask();
        await WaitUntilAsync(() => output.ToString().Contains("handshake.ready", StringComparison.Ordinal));
        connection.PeerStream.AppendInput(PeerFrames.Inventory("inv", transactionId));
        await WaitUntilAsync(() => output.ToString().Contains("\"fact\":\"Requested\"", StringComparison.Ordinal));
        connection.PeerStream.EndInput();

        var exit = await running.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreEqual(CliExitCode.PeerSessionFailure, exit);
        Assert.IsFalse(output.ToString().Contains("\"fact\":\"Received\"", StringComparison.Ordinal));
        StringAssert.Contains(Lines(output)[^1], "\"outcome\":\"transport_terminal\"");
        StringAssert.Contains(Lines(output)[^1], "PeerClosed");
    }

    [TestMethod]
    public async Task CancellationAfterRequestPreservesRequestedFactButNotReceipt()
    {
        var transactionId = Hash256.DoubleSha256(TransactionFixture.CreateMinimal());
        var connection = new FakePeerConnection(PeerFrames.Ready());
        var output = new ThreadSafeStringWriter();
        var application = CreateApplication(connection, output, new TestRuntime());
        using var cancellation = new CancellationTokenSource();

        var running = application.RunAsync(CreateArguments(transactionId), cancellation.Token).AsTask();
        await WaitUntilAsync(() => output.ToString().Contains("handshake.ready", StringComparison.Ordinal));
        connection.PeerStream.AppendInput(PeerFrames.Inventory("inv", transactionId));
        await WaitUntilAsync(() => output.ToString().Contains("\"fact\":\"Requested\"", StringComparison.Ordinal));
        cancellation.Cancel();

        var exit = await running.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreEqual(CliExitCode.Canceled, exit);
        CollectionAssert.AreEqual(
            new[] { BsvTransactionFetchOutputKind.Requested.ToString() },
            ReadFacts(output));
        StringAssert.Contains(Lines(output)[^1], "\"outcome\":\"canceled\"");
        Assert.IsFalse(output.ToString().Contains("\"fact\":\"Received\"", StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task MonetaryInvalidTargetIsReportedButNeverReceived()
    {
        var transaction = TransactionFixture.CreateMinimal(-1);
        var transactionId = Hash256.DoubleSha256(transaction);
        var connection = new FakePeerConnection(PeerFrames.Ready());
        var output = new ThreadSafeStringWriter();
        var application = CreateApplication(connection, output, new TestRuntime());

        var running = application.RunAsync(CreateArguments(transactionId), CancellationToken.None).AsTask();
        await WaitUntilAsync(() => output.ToString().Contains("handshake.ready", StringComparison.Ordinal));
        connection.PeerStream.AppendInput(PeerFrames.Inventory("inv", transactionId));
        await WaitUntilAsync(() => HasOutboundCommand(connection, "getdata"));
        connection.PeerStream.AppendInput(PeerFrames.Transaction(transaction));

        var exit = await running.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreEqual(CliExitCode.PeerSessionFailure, exit);
        StringAssert.Contains(output.ToString(), "transaction.monetary-validation");
        Assert.IsFalse(output.ToString().Contains("\"fact\":\"Received\"", StringComparison.Ordinal));
        StringAssert.Contains(Lines(output)[^1], "\"reason\":\"monetary_invalid\"");
    }

    [TestMethod]
    public async Task FactOutputFailureCannotFabricateReceiptSuccess()
    {
        var transaction = TransactionFixture.CreateMinimal();
        var transactionId = Hash256.DoubleSha256(transaction);
        var connection = new FakePeerConnection(PeerFrames.Ready());
        var output = new ThrowOnceOnContentWriter("\"fact\":\"Received\"");
        var application = CreateApplication(connection, output, new TestRuntime());

        var running = application.RunAsync(CreateArguments(transactionId), CancellationToken.None).AsTask();
        await WaitUntilAsync(() => output.ToString().Contains("handshake.ready", StringComparison.Ordinal));
        connection.PeerStream.AppendInput(PeerFrames.Inventory("inv", transactionId));
        await WaitUntilAsync(() => HasOutboundCommand(connection, "getdata"));
        connection.PeerStream.AppendInput(PeerFrames.Transaction(transaction));

        var exit = await running.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreEqual(CliExitCode.InternalError, exit);
        Assert.IsFalse(output.ToString().Contains("session.stopped", StringComparison.Ordinal));
        StringAssert.Contains(Lines(output)[^1], "FactSinkFailure");
    }

    private static FetchReferenceCliApplication CreateApplication(
        FakePeerConnection connection,
        TextWriter output,
        IReferenceCliRuntime runtime) =>
        new(new FakePeerConnector(connection), runtime, output, new ThreadSafeStringWriter());

    private static CliArguments CreateArguments(Hash256 transactionId) =>
        new(
            ReferenceCliCommand.Fetch,
            new PeerEndpoint("node.example", 8333),
            null,
            TimeSpan.FromSeconds(5),
            TimeSpan.FromSeconds(30),
            TransactionId: transactionId,
            FetchTimeout: TimeSpan.FromSeconds(30));

    private static byte[] CreateInventoryPayload(Hash256 transactionId)
    {
        var payload = new byte[1 + InventoryVectorCodec.EncodedLength];
        var vectors = new[] { new InventoryVector(1, transactionId) };
        Assert.AreEqual(
            System.Buffers.OperationStatus.Done,
            InventoryPayloadCodec.TryWrite(vectors, payload, (ulong)payload.Length, out var written));
        Assert.AreEqual(payload.Length, written);
        return payload;
    }

    private static string[] ReadTypes(StringWriter output) =>
        Lines(output).Select(static line =>
        {
            using var document = JsonDocument.Parse(line);
            return document.RootElement.GetProperty("type").GetString()!;
        }).ToArray();

    private static string[] ReadFacts(StringWriter output) =>
        Lines(output).Select(static line => JsonDocument.Parse(line))
            .Where(static document => document.RootElement.GetProperty("type").GetString() == "fetch.fact")
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

    private sealed class ThrowOnceOnContentWriter(string content) : ThreadSafeStringWriter
    {
        private int _thrown;

        public override Task WriteLineAsync(
            ReadOnlyMemory<char> buffer,
            CancellationToken cancellationToken = default)
        {
            if (buffer.Span.Contains(content, StringComparison.Ordinal) &&
                Interlocked.Exchange(ref _thrown, 1) == 0)
            {
                throw new IOException("fetch stdout failed");
            }

            return base.WriteLineAsync(buffer, cancellationToken);
        }
    }

    private sealed class BlockingOnContentWriter(string content) : ThreadSafeStringWriter
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
}
