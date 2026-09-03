using System.Buffers;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Xml.Linq;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Encoding;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Messages;
using Staffetta.Core.Protocol.Sessions;
using Staffetta.Core.Protocol.Transactions;
using Staffetta.Core.Protocol.Wire;

if (args.Length != 2)
{
    throw new ArgumentException("Expected the local package path and repository commit.");
}

using ZipArchive package = ZipFile.OpenRead(args[0]);
string feedDirectory = Path.GetDirectoryName(Path.GetFullPath(args[0]))!;
Require(Directory.EnumerateFiles(feedDirectory, "*", SearchOption.AllDirectories).Count() == 1, "Solution emitted unexpected packages or artifacts.");
string[] requiredEntries =
[
    "[Content_Types].xml",
    "_rels/.rels",
    "Staffetta.Core.nuspec",
    "README.md",
    "LICENSE",
    "lib/net10.0/Staffetta.Core.dll",
    "lib/net10.0/Staffetta.Core.xml",
];
foreach (string name in requiredEntries)
{
    Require(package.Entries.Count(entry => entry.FullName == name) == 1, $"Missing or duplicate package entry: {name}.");
}

foreach (ZipArchiveEntry entry in package.Entries)
{
    Require(
        requiredEntries.Contains(entry.FullName, StringComparer.Ordinal) ||
        (entry.FullName.StartsWith("package/services/metadata/core-properties/", StringComparison.Ordinal) &&
         entry.FullName.EndsWith(".psmdcp", StringComparison.Ordinal)),
        $"Unexpected package content: {entry.FullName}.");
}

using (Stream nuspecStream = package.GetEntry("Staffetta.Core.nuspec")!.Open())
{
    XDocument nuspec = XDocument.Load(nuspecStream);
    XNamespace ns = nuspec.Root!.Name.Namespace;
    XElement metadata = nuspec.Root.Element(ns + "metadata")!;
    Require(metadata.Element(ns + "id")?.Value == "Staffetta.Core", "Wrong package id.");
    Require(metadata.Element(ns + "version")?.Value == "0.0.0-smoke", "Wrong smoke package version.");
    Require(metadata.Element(ns + "license")?.Value == "Apache-2.0", "Missing license expression.");
    Require(metadata.Element(ns + "license")?.Attribute("type")?.Value == "expression", "Wrong license type.");
    Require(metadata.Element(ns + "readme")?.Value == "README.md", "Missing package README declaration.");
    Require(metadata.Element(ns + "repository")?.Attribute("commit")?.Value == args[1], "Repository commit was not embedded.");
    Require(!metadata.Descendants(ns + "dependency").Any(), "Core unexpectedly acquired a runtime package dependency.");
}

using (Stream documentation = package.GetEntry("lib/net10.0/Staffetta.Core.xml")!.Open())
{
    XDocument xml = XDocument.Load(documentation);
    Require(xml.Root?.Element("assembly")?.Element("name")?.Value == "Staffetta.Core", "Wrong XML documentation assembly.");
    Require(
        xml.Descendants("member").Any(member => member.Attribute("name")?.Value == "T:Staffetta.Core.Protocol.Blocks.MerkleInclusionVerifier"),
        "Public Merkle documentation is missing from the package.");
}

using (Stream packedAssembly = package.GetEntry("lib/net10.0/Staffetta.Core.dll")!.Open())
using (Stream loadedAssembly = File.OpenRead(typeof(Hash256).Assembly.Location))
{
    Require(SHA256.HashData(packedAssembly).AsSpan().SequenceEqual(SHA256.HashData(loadedAssembly)), "Consumer did not load the packaged assembly.");
}

Span<byte> encoded = stackalloc byte[9];
Require(CompactSize.Write(ulong.MaxValue, encoded, out int written) == OperationStatus.Done && written == 9, "Public CompactSize write failed.");
Require(CompactSize.Read(encoded, out ulong decoded, out int consumed) == OperationStatus.Done && decoded == ulong.MaxValue && consumed == 9, "Public CompactSize read failed.");
byte[] readmeBytes = [0xfd, 0xfd, 0x00];
Require(CompactSize.Read(readmeBytes, out ulong readmeValue, out int readmeConsumed) == OperationStatus.Done && readmeValue == 253 && readmeConsumed == 3, "README example failed.");

Hash256 txid = Hash256.DoubleSha256("package-smoke"u8);
Require(MerkleInclusionVerifier.Verify(txid, 0, [], txid) == MerkleInclusionVerification.Verified, "Public inclusion check failed.");
Require(MerkleInclusionVerifier.Verify(txid, 1, [], txid) == MerkleInclusionVerification.TransactionIndexHasUnprovenHighBits, "Public inclusion failure contract changed.");

byte[] magic = [0xe3, 0xe1, 0xf3, 0xe8];
var observationSink = new ObservationSink();
using (var session = new BsvPeerObservationSession(magic, 1_048_576, 70001, observationSink, 2, 2))
{
    var version = new VersionPayload(70016, 0, 1, default, default, 1, "smoke"u8, 0, true);
    Require(session.StartHandshake(version, 1_048_576) == OperationStatus.Done, "Public observation handshake start failed.");
    Flush(session);
    var peerVersion = new VersionPayload(70016, 0, 1, default, default, 2, "smoke"u8, 0, true);
    Span<byte> peerPayload = stackalloc byte[128];
    Require(VersionPayloadCodec.TryWrite(peerPayload, peerVersion, out int peerLength) == OperationStatus.Done, "Version encode failed.");
    Require(session.Consume(Frame(magic, "version"u8, peerPayload[..peerLength]), out _) == OperationStatus.Done, "Peer version failed.");
    Flush(session);
    Require(session.Consume(Frame(magic, "verack"u8, []), out _) == OperationStatus.Done, "Peer verack failed.");
    Flush(session);
    Require(session.HandshakeState == BsvHandshakeState.Ready, "Observation session is not ready.");
    Require(session.RequestTransaction(txid) == OperationStatus.Done, "Explicit public transaction request failed.");
    Flush(session);
    Require(!session.HasPendingInventory, "Request manufactured inventory.");
    Require(session.RequestHeaders([txid]) == OperationStatus.Done, "Public headers request failed.");
    Flush(session);
    Span<byte> inventoryPayload = stackalloc byte[37];
    Require(InventoryPayloadCodec.TryWrite([new InventoryVector(1, txid)], inventoryPayload, 37, out _) == OperationStatus.Done, "Inventory encode failed.");
    Require(session.Consume(Frame(magic, "inv"u8, inventoryPayload), out _) == OperationStatus.Done && session.PendingInventoryCount == 1, "Validated public inventory failed.");
    Span<InventoryVector> inventory = stackalloc InventoryVector[1];
    Require(session.DrainInventory(inventory, out _) == OperationStatus.Done && inventory[0].Hash == txid, "Inventory drain failed.");
    Require(session.Consume(Frame(magic, "headers"u8, [0]), out _) == OperationStatus.Done && session.HasPendingHeaders, "Empty validated headers not surfaced.");
    Require(session.DrainHeaders([], out _) == OperationStatus.Done, "Headers drain failed.");
    byte[] transaction = new byte[61];
    transaction[0] = transaction[4] = transaction[46] = transaction[47] = transaction[55] = 1;
    transaction[56] = 0x51;
    Require(session.Consume(Frame(magic, "tx"u8, transaction), out _) == OperationStatus.Done, "Public transaction intake failed.");
    Require(observationSink.TransactionId == Hash256.DoubleSha256(transaction) && observationSink.Commits == 1, "Public transaction commit identity failed.");
}

Require(!BsvSelectedHeaderChain.TryCreateTrustedBootstrap([], out _), "Empty trusted bootstrap created authority.");
Require(!typeof(BsvPeerObservationSession).Assembly.GetExportedTypes().Any(type => type.Name is "BsvPeerStreamTransportActor" or "BsvPeerSessionEgressPlanner"), "Internal transport runtime leaked into public API.");
Console.WriteLine("Package smoke passed: isolated local restore, public observation consumer, DLL/XML, license, README, provenance, and archive allowlist.");

static void Flush(BsvPeerObservationSession session)
{
    while (session.TryGetWrite(out var lease))
    {
        Require(!lease.Bytes.IsEmpty, "Empty public write lease.");
        Require(session.AcknowledgeWrite(lease, lease.Bytes.Length) == OperationStatus.Done, "Public lease acknowledgement failed.");
    }
}

static byte[] Frame(ReadOnlySpan<byte> magic, ReadOnlySpan<byte> command, ReadOnlySpan<byte> payload)
{
    var frame = new byte[24 + payload.Length];
    Span<byte> checksum = stackalloc byte[4];
    _ = MessageChecksum.Compute(payload).TryCopyTo(checksum, out _);
    Require(MessageHeader.TryCreateBasic(command, (uint)payload.Length, checksum, out var header) == OperationStatus.Done, "Frame header failed.");
    Require(MessageHeaderCodec.TryWrite(frame, magic, header, 1_048_576, out _) == OperationStatus.Done, "Frame encode failed.");
    payload.CopyTo(frame.AsSpan(24));
    return frame;
}

static void Require(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidDataException(message);
    }
}

sealed class ObservationSink : ILegacyTransactionSink
{
    internal Hash256 TransactionId { get; private set; }
    internal int Commits { get; private set; }
    public void OnTransactionStarted(int version, ulong inputCount) { }
    public void OnInputStarted(ulong inputIndex, in OutPoint previousOutput, ulong scriptLength) { }
    public void OnInputScriptChunk(ulong inputIndex, ReadOnlySpan<byte> script) { }
    public void OnInputCompleted(ulong inputIndex, uint sequence) { }
    public void OnOutputsStarted(ulong outputCount) { }
    public void OnOutputStarted(ulong outputIndex, long valueSatoshis, ulong scriptLength) { }
    public void OnOutputScriptChunk(ulong outputIndex, ReadOnlySpan<byte> script) { }
    public void OnOutputCompleted(ulong outputIndex) { }
    public void OnTransactionCommitted(in LegacyTransactionSummary summary) { TransactionId = summary.TransactionId; Commits++; }
    public void OnTransactionAborted() { }
}
