using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Staffetta.Bsv.LiveProbe.Tests;

[TestClass]
public sealed class CandidateArtifactTests
{
    private const string Locator =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    [TestMethod]
    public async Task ValidFixturePublishesBinAndManifestAsOneDirectory()
    {
        var output = CreateOutputPath();
        try
        {
            var options = ParseOptions(output, Locator);
            await using var artifact = CandidateArtifact.Create(output);
            await using (var fixture = File.OpenRead(GetFixturePath()))
            {
                await fixture.CopyToAsync(artifact.Stream);
            }

            var evidence = await artifact.ValidateAsync(options.Locator, CancellationToken.None);
            Assert.AreEqual(2_000, evidence.Count);
            Assert.AreEqual(162_003, evidence.PayloadLength);
            await artifact.PublishAsync(CreateManifest(options, evidence), CancellationToken.None);

            Assert.IsTrue(Directory.Exists(output));
            Assert.IsFalse(Directory.Exists(output + ".part"));
            Assert.IsTrue(File.Exists(Path.Combine(output, "candidate.bin")));
            Assert.IsTrue(File.Exists(Path.Combine(output, "candidate.json")));
            Assert.IsFalse(File.Exists(Path.Combine(output, "candidate.bin.part")));
            Assert.IsFalse(File.Exists(Path.Combine(output, "candidate.json.part")));
        }
        finally
        {
            DeleteTestPaths(output);
        }
    }

    [TestMethod]
    public async Task WrongLocatorLeavesOnlyUnpublishedStagingCandidate()
    {
        var output = CreateOutputPath();
        try
        {
            var options = ParseOptions(
                output,
                "0000000000000000000000000000000000000000000000000000000000000001");
            await using var artifact = CandidateArtifact.Create(output);
            await using (var fixture = File.OpenRead(GetFixturePath()))
            {
                await fixture.CopyToAsync(artifact.Stream);
            }

            await Assert.ThrowsExceptionAsync<InvalidDataException>(() =>
                artifact.ValidateAsync(options.Locator, CancellationToken.None));

            Assert.IsFalse(Directory.Exists(output));
            Assert.IsTrue(Directory.Exists(output + ".part"));
            Assert.IsTrue(File.Exists(Path.Combine(output + ".part", "candidate.bin.part")));
            Assert.IsFalse(File.Exists(Path.Combine(output + ".part", "candidate.bin")));
        }
        finally
        {
            DeleteTestPaths(output);
        }
    }

    [TestMethod]
    public async Task TrailingByteIsRejectedWithoutPublishingCanonicalNames()
    {
        var output = CreateOutputPath();
        try
        {
            var options = ParseOptions(output, Locator);
            await using var artifact = CandidateArtifact.Create(output);
            await using (var fixture = File.OpenRead(GetFixturePath()))
            {
                await fixture.CopyToAsync(artifact.Stream);
            }

            artifact.Stream.WriteByte(0);
            await Assert.ThrowsExceptionAsync<InvalidDataException>(() =>
                artifact.ValidateAsync(options.Locator, CancellationToken.None));
            Assert.IsFalse(Directory.Exists(output));
            Assert.IsFalse(File.Exists(Path.Combine(output + ".part", "candidate.bin")));
        }
        finally
        {
            DeleteTestPaths(output);
        }
    }

    [TestMethod]
    public async Task ExistingOutputOrStagingPathIsNeverReused()
    {
        var output = CreateOutputPath();
        Directory.CreateDirectory(output);
        try
        {
            Assert.ThrowsException<IOException>(() => CandidateArtifact.Create(output));
            Directory.Delete(output);
            Directory.CreateDirectory(output + ".part");
            Assert.ThrowsException<IOException>(() => CandidateArtifact.Create(output));
        }
        finally
        {
            DeleteTestPaths(output);
        }

        await Task.CompletedTask;
    }

    private static ProbeManifest CreateManifest(ProbeOptions options, HeadersEvidence evidence) =>
        new(
            2,
            "commit",
            "dirty",
            ".NET test",
            "test OS",
            options.Peer.ToString(),
            options.Peer.ToString(),
            DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch.AddSeconds(1),
            new Dictionary<string, long> { ["headers"] = 1 },
            70_015,
            new PeerUserAgent("/peer/", 6, new string('0', 64)),
            options.LocatorHex,
            1,
            false,
            ["headers"],
            new N2Observations("absent", "not_observed", "not_stimulated_by_policy", "validated_exact", "validated_exact"),
            new AddressDiscoveryEvidence(
                "executed_once",
                "observed_and_parsed",
                "peer_advertised_unverified",
                0,
                0,
                []),
            evidence,
            new Dictionary<string, string> { ["transaction_broadcast"] = "not_run_by_policy" });

    private static ProbeOptions ParseOptions(string output, string locator) => ProbeOptions.Parse(
        ["--peer", "127.0.0.1:8333", "--locator", locator, "--output", output]);

    private static string GetFixturePath() => Path.Combine(
        AppContext.BaseDirectory,
        "Fixtures",
        "Bsv",
        "headers-mainnet-after-genesis-2000-20260830.bin");

    private static string CreateOutputPath() => Path.Combine(
        Path.GetTempPath(),
        "staffetta-live-probe-tests",
        Guid.NewGuid().ToString("N"),
        "capture");

    private static void DeleteTestPaths(string output)
    {
        if (Directory.Exists(output))
        {
            Directory.Delete(output, recursive: true);
        }

        if (Directory.Exists(output + ".part"))
        {
            Directory.Delete(output + ".part", recursive: true);
        }

        var parent = Directory.GetParent(output)?.FullName;
        if (parent is not null && Directory.Exists(parent))
        {
            Directory.Delete(parent, recursive: true);
        }
    }
}
