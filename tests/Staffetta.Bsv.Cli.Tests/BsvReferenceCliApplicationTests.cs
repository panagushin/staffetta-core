using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Staffetta.Bsv.Cli.Tests;

[TestClass]
public sealed class BsvReferenceCliApplicationTests
{
    private static readonly string[] ExpectedOutboundHandshakeCommands =
        ["version", "verack", "protoconf"];

    private static readonly string[] ExpectedHandshakeOutputLines =
    [
        "{\"schema\":\"staffetta.bsv.reference-cli.event.v1\",\"sequence\":1,\"type\":\"connection.opened\",\"requestedPeer\":\"node.example:8333\",\"remotePeer\":\"192.0.2.10:8333\"}",
        "{\"schema\":\"staffetta.bsv.reference-cli.event.v1\",\"sequence\":2,\"type\":\"handshake.ready\",\"peer\":\"192.0.2.10:8333\",\"protocolVersion\":70016,\"effectivePeerMaximumReceivePayloadLength\":\"1048576\",\"peerProtoconfObserved\":false}",
        "{\"schema\":\"staffetta.bsv.reference-cli.event.v1\",\"sequence\":3,\"type\":\"session.stopped\",\"reason\":\"completed\"}",
    ];

    [TestMethod]
    public async Task HandshakeWritesExactTruthAndOnlyHandshakeCommands()
    {
        var connection = new FakePeerConnection(PeerFrames.Ready());
        var connector = new FakePeerConnector(connection);
        var output = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
        var application = CreateApplication(connector, output, new TestRuntime());

        var exit = await application.RunAsync(CreateHandshakeArguments(), CancellationToken.None);

        Assert.AreEqual(CliExitCode.Success, exit);
        var lines = Lines(output);
        CollectionAssert.AreEqual(
            ExpectedHandshakeOutputLines,
            lines);
        CollectionAssert.AreEqual(
            ExpectedOutboundHandshakeCommands,
            PeerFrames.ReadOutboundCommands(connection.PeerStream.WrittenBytes));
        Assert.AreEqual(1, connection.AbortCount);
        Assert.AreEqual(1, connection.DisposeCount);
    }

    [TestMethod]
    public async Task PrepareBroadcastIsStrictlyLocalAndNeverConstructsAPeerSession()
    {
        var path = await TransactionFixture.WriteTempAsync(2 * 1024 * 1024);
        try
        {
            var connectorFactoryCalls = 0;
            var output = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
            Assert.IsTrue(CliArguments.TryParse(
                ["prepare-broadcast", "--tx-file", path],
                out var arguments,
                out _,
                out var error), error);

            var exit = await ReferenceCliDispatcher.RunAsync(
                arguments!,
                () =>
                {
                    connectorFactoryCalls++;
                    throw new AssertFailedException("connector constructed");
                },
                new TestRuntime(),
                output,
                new ThreadSafeStringWriter(),
                CancellationToken.None);

            Assert.AreEqual(CliExitCode.Success, exit);
            Assert.AreEqual(0, connectorFactoryCalls);
            var lines = Lines(output);
            Assert.HasCount(1, lines);
            using var document = JsonDocument.Parse(lines[0]);
            var root = document.RootElement;
            Assert.AreEqual("broadcast.prepared", root.GetProperty("type").GetString());
            Assert.AreEqual("false", root.GetProperty("willBroadcast").GetRawText());
            Assert.AreEqual(new FileInfo(path).Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
                root.GetProperty("transactionLength").GetString());
            Assert.IsFalse(lines[0].Contains(path, StringComparison.Ordinal));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task MalformedLocalInputReturnsThreeWithoutConnecting()
    {
        var path = Path.Combine(Path.GetTempPath(), $"staffetta-cli-{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(path, new byte[] { 1, 2, 3 });
        try
        {
            var connectorFactoryCalls = 0;
            var output = new ThreadSafeStringWriter();
            var arguments = new CliArguments(
                ReferenceCliCommand.PrepareBroadcast,
                default,
                path,
                TimeSpan.FromSeconds(5),
                TimeSpan.FromSeconds(30));

            var exit = await ReferenceCliDispatcher.RunAsync(
                arguments,
                () =>
                {
                    connectorFactoryCalls++;
                    throw new AssertFailedException("connector constructed");
                },
                new TestRuntime(),
                output,
                new ThreadSafeStringWriter(),
                CancellationToken.None);

            Assert.AreEqual(CliExitCode.TransactionInput, exit);
            Assert.AreEqual(0, connectorFactoryCalls);
            Assert.AreEqual(string.Empty, output.ToString());
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task MonetaryInvalidBroadcastReturnsThreeBeforeConnectorConstruction()
    {
        var path = await TransactionFixture.WriteTempAsync(outputValueSatoshis: -1);
        try
        {
            var connectorFactoryCalls = 0;
            var output = new ThreadSafeStringWriter();
            var error = new ThreadSafeStringWriter();
            var arguments = new CliArguments(
                ReferenceCliCommand.Broadcast,
                new PeerEndpoint("node.example", 8333),
                path,
                TimeSpan.FromSeconds(5),
                TimeSpan.FromSeconds(30),
                TimeSpan.FromSeconds(30));

            var exit = await ReferenceCliDispatcher.RunAsync(
                arguments,
                () =>
                {
                    connectorFactoryCalls++;
                    throw new AssertFailedException("connector constructed");
                },
                new TestRuntime(),
                output,
                error,
                CancellationToken.None);

            Assert.AreEqual(CliExitCode.TransactionInput, exit);
            Assert.AreEqual(0, connectorFactoryCalls);
            Assert.AreEqual(string.Empty, output.ToString());
            StringAssert.Contains(error.ToString(), "NegativeOutput");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public async Task SilentHandshakeTimeoutStopsBeforeForcedSocketClose()
    {
        var connection = new FakePeerConnection([]);
        var connector = new FakePeerConnector(connection);
        var output = new ThreadSafeStringWriter();
        var runtime = new TestRuntime(TestRuntime.Infinite, TestRuntime.Immediate);
        var application = CreateApplication(connector, output, runtime);

        var exit = await application.RunAsync(CreateHandshakeArguments(), CancellationToken.None);

        Assert.AreEqual(CliExitCode.Timeout, exit);
        Assert.AreEqual(1, connection.AbortCount);
        Assert.AreEqual(1, connection.DisposeCount);
        var lines = Lines(output);
        Assert.HasCount(2, lines);
        StringAssert.Contains(lines[1], "\"kind\":\"timeout\"");
        Assert.IsFalse(lines.Any(line => line.Contains("handshake.ready", StringComparison.Ordinal)));
    }

    [TestMethod]
    public async Task OperatorCancellationWinsBeforeForcedClose()
    {
        var connection = new FakePeerConnection([]);
        var output = new ThreadSafeStringWriter();
        var application = CreateApplication(
            new FakePeerConnector(connection),
            output,
            new TestRuntime());
        using var cancellation = new CancellationTokenSource();
        var running = application.RunAsync(CreateHandshakeArguments(), cancellation.Token).AsTask();
        await connection.PeerStream.ReadPending.WaitAsync(TimeSpan.FromSeconds(5));

        cancellation.Cancel();
        var exit = await running.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreEqual(CliExitCode.Canceled, exit);
        Assert.AreEqual(1, connection.AbortCount);
        Assert.AreEqual(1, connection.DisposeCount);
        StringAssert.Contains(Lines(output)[1], "\"kind\":\"canceled\"");
    }

    [TestMethod]
    public async Task EofBeforeReadyIsATruthfulPeerSessionFailure()
    {
        var connection = new FakePeerConnection([], endWithEof: true);
        var output = new ThreadSafeStringWriter();
        var application = CreateApplication(
            new FakePeerConnector(connection),
            output,
            new TestRuntime());

        var exit = await application.RunAsync(CreateHandshakeArguments(), CancellationToken.None);

        Assert.AreEqual(CliExitCode.PeerSessionFailure, exit);
        var lines = Lines(output);
        Assert.HasCount(2, lines);
        StringAssert.Contains(lines[1], "\"type\":\"session.terminal\"");
        StringAssert.Contains(lines[1], "PeerClosed");
    }

    [TestMethod]
    public async Task PeerRejectIsReportedByTheExactHandshakeTerminalReason()
    {
        var connection = new FakePeerConnection(PeerFrames.Rejected());
        var output = new ThreadSafeStringWriter();
        var application = CreateApplication(
            new FakePeerConnector(connection),
            output,
            new TestRuntime());

        var exit = await application.RunAsync(CreateHandshakeArguments(), CancellationToken.None);

        Assert.AreEqual(CliExitCode.PeerSessionFailure, exit);
        var lines = Lines(output);
        Assert.HasCount(2, lines);
        StringAssert.Contains(lines[1], "\"type\":\"session.terminal\"");
        StringAssert.Contains(lines[1], "RejectBeforeReady");
    }

    [TestMethod]
    public async Task CancellationIgnoringLateConnectorCannotStrandTheCommand()
    {
        var late = new TaskCompletionSource<IPeerConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
        var connection = new FakePeerConnection([]);
        var connector = new FakePeerConnector(_ => new ValueTask<IPeerConnection>(late.Task));
        var application = CreateApplication(
            connector,
            new ThreadSafeStringWriter(),
            new TestRuntime(TestRuntime.Immediate));

        var exit = await application.RunAsync(CreateHandshakeArguments(), CancellationToken.None);

        Assert.AreEqual(CliExitCode.Timeout, exit);
        late.SetResult(connection);
        await connection.Disposed.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.AreEqual(1, connection.AbortCount);
        Assert.AreEqual(1, connection.DisposeCount);
    }

    [TestMethod]
    public async Task BrokenStdoutDuringReadyProducesNoFabricatedTerminalLine()
    {
        var connection = new FakePeerConnection(PeerFrames.Ready());
        var output = new ThrowOnSecondLineWriter();
        var application = CreateApplication(
            new FakePeerConnector(connection),
            output,
            new TestRuntime());

        var exit = await application.RunAsync(CreateHandshakeArguments(), CancellationToken.None);

        Assert.AreEqual(CliExitCode.InternalError, exit);
        Assert.AreEqual(1, output.CompletedLineCount);
    }

    [TestMethod]
    public async Task FlushFailureAfterWrittenConnectionLineCannotFabricateLaterTruth()
    {
        var connection = new FakePeerConnection(PeerFrames.Ready());
        var output = new ThrowOnFlushWriter();
        var application = CreateApplication(
            new FakePeerConnector(connection),
            output,
            new TestRuntime());

        var exit = await application.RunAsync(CreateHandshakeArguments(), CancellationToken.None);

        Assert.AreEqual(CliExitCode.InternalError, exit);
        Assert.AreEqual(1, output.CompletedLineCount);
        var written = output.ToString();
        StringAssert.Contains(written, "connection.opened");
        Assert.IsFalse(written.Contains("handshake.ready", StringComparison.Ordinal));
        Assert.IsFalse(written.Contains("session.terminal", StringComparison.Ordinal));
        Assert.AreEqual(0, connection.AbortCount);
        Assert.AreEqual(1, connection.DisposeCount);
    }

    [TestMethod]
    public async Task FaultedHandshakeDelayPreservesInternalFailureAndCleansUp()
    {
        var connection = new FakePeerConnection([]);
        var output = new ThreadSafeStringWriter();
        var runtime = new TestRuntime(
            TestRuntime.Infinite,
            _ => Task.FromException(new InvalidOperationException("clock")));
        var application = CreateApplication(new FakePeerConnector(connection), output, runtime);

        var exit = await application.RunAsync(CreateHandshakeArguments(), CancellationToken.None);

        Assert.AreEqual(CliExitCode.InternalError, exit);
        Assert.AreEqual(1, connection.AbortCount);
        Assert.AreEqual(1, connection.DisposeCount);
        Assert.HasCount(1, Lines(output));
    }

    [TestMethod]
    public async Task FaultedConnectDelayDisposesSimultaneousSuccessfulConnection()
    {
        var connection = new FakePeerConnection([]);
        var output = new ThreadSafeStringWriter();
        var application = CreateApplication(
            new FakePeerConnector(connection),
            output,
            new TestRuntime(_ => Task.FromException(new InvalidOperationException("clock"))));

        var exit = await application.RunAsync(CreateHandshakeArguments(), CancellationToken.None);

        Assert.AreEqual(CliExitCode.InternalError, exit);
        Assert.AreEqual(1, connection.AbortCount);
        Assert.AreEqual(1, connection.DisposeCount);
        Assert.AreEqual(string.Empty, output.ToString());
    }

    [TestMethod]
    public async Task CancellationAtConnectSuccessEmitsNoConnectionSuccess()
    {
        using var cancellation = new CancellationTokenSource();
        var connection = new FakePeerConnection([]);
        var connector = new FakePeerConnector(_ =>
        {
            cancellation.Cancel();
            return ValueTask.FromResult<IPeerConnection>(connection);
        });
        var output = new ThreadSafeStringWriter();
        var application = CreateApplication(connector, output, new TestRuntime());

        var exit = await application.RunAsync(CreateHandshakeArguments(), cancellation.Token);

        Assert.AreEqual(CliExitCode.Canceled, exit);
        Assert.AreEqual(1, connection.AbortCount);
        Assert.AreEqual(1, connection.DisposeCount);
        var lines = Lines(output);
        Assert.HasCount(1, lines);
        StringAssert.Contains(lines[0], "\"stage\":\"connect\"");
        Assert.IsFalse(lines[0].Contains("connection.opened", StringComparison.Ordinal));
    }

    private static BsvReferenceCliApplication CreateApplication(
        IPeerConnector connector,
        TextWriter output,
        IReferenceCliRuntime runtime) =>
        new(connector, runtime, output, new ThreadSafeStringWriter());

    private static CliArguments CreateHandshakeArguments() =>
        new(
            ReferenceCliCommand.Handshake,
            new PeerEndpoint("node.example", 8333),
            null,
            TimeSpan.FromSeconds(5),
            TimeSpan.FromSeconds(30));

    private static string[] Lines(StringWriter output) =>
        output.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);

    private sealed class ThrowOnSecondLineWriter : StringWriter
    {
        internal int CompletedLineCount { get; private set; }

        public override Task WriteLineAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default)
        {
            if (CompletedLineCount != 0)
            {
                throw new IOException("broken stdout");
            }

            CompletedLineCount++;
            return base.WriteLineAsync(buffer, cancellationToken);
        }
    }

    private sealed class ThrowOnFlushWriter : StringWriter
    {
        internal int CompletedLineCount { get; private set; }

        public override Task WriteLineAsync(ReadOnlyMemory<char> buffer, CancellationToken cancellationToken = default)
        {
            CompletedLineCount++;
            return base.WriteLineAsync(buffer, cancellationToken);
        }

        public override Task FlushAsync(CancellationToken cancellationToken) =>
            Task.FromException(new IOException("flush failed"));
    }
}
