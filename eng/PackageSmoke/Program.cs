using System.Buffers;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Xml.Linq;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Encoding;

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

Console.WriteLine("Package smoke passed: isolated local restore, public consumer, DLL/XML, license, README, provenance, and archive allowlist.");

static void Require(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidDataException(message);
    }
}
