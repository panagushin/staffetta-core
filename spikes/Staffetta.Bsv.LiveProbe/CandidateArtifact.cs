using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Bsv.LiveProbe;

internal sealed class CandidateArtifact : IAsyncDisposable
{
    internal const int MaximumHeadersPayloadLength = 3 +
        (HeadersPayloadCodec.MaximumHeaderCount * (BlockHeaderCodec.EncodedLength + 1));

    private readonly string _outputDirectory;
    private readonly string _stagingDirectory;
    private readonly string _partPath;
    private FileStream? _stream;
    private bool _published;

    private CandidateArtifact(string outputDirectory, string stagingDirectory, FileStream stream)
    {
        _outputDirectory = outputDirectory;
        _stagingDirectory = stagingDirectory;
        _partPath = Path.Combine(stagingDirectory, "candidate.bin.part");
        _stream = stream;
    }

    internal Stream Stream => _stream ?? throw new ObjectDisposedException(nameof(CandidateArtifact));

    internal static CandidateArtifact Create(string outputDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        var stagingDirectory = outputDirectory + ".part";
        if (File.Exists(outputDirectory) ||
            Directory.Exists(outputDirectory) ||
            File.Exists(stagingDirectory) ||
            Directory.Exists(stagingDirectory))
        {
            throw new IOException("Neither the output path nor its staging path may already exist.");
        }

        Directory.CreateDirectory(stagingDirectory);
        var attributes = File.GetAttributes(stagingDirectory);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("The output directory must not be a symbolic link or reparse point.");
        }

        var partPath = Path.Combine(stagingDirectory, "candidate.bin.part");
        var stream = new FileStream(
            partPath,
            FileMode.CreateNew,
            FileAccess.ReadWrite,
            FileShare.None,
            ProbeTransport.BufferLength,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return new CandidateArtifact(outputDirectory, stagingDirectory, stream);
    }

    internal async Task<HeadersEvidence> ValidateAsync(
        Hash256 requestedLocator,
        CancellationToken cancellationToken)
    {
        var stream = _stream ?? throw new ObjectDisposedException(nameof(CandidateArtifact));
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (stream.Length > MaximumHeadersPayloadLength)
        {
            throw new InvalidDataException("The headers payload exceeds the canonical 2,000-header bound.");
        }

        var payload = GC.AllocateUninitializedArray<byte>(checked((int)stream.Length));
        stream.Position = 0;
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);

        var headers = new BlockHeader[HeadersPayloadCodec.MaximumHeaderCount];
        var status = HeadersPayloadCodec.TryParse(payload, headers, out var count);
        if (status != OperationStatus.Done)
        {
            throw new InvalidDataException($"HeadersPayloadCodec rejected the candidate with status {status}.");
        }

        if (count == 0 || headers[0].PreviousBlockHash != requestedLocator)
        {
            throw new InvalidDataException("The headers candidate does not continue the requested locator.");
        }

        var linkageValid = true;
        for (var index = 1; index < count; index++)
        {
            if (headers[index].PreviousBlockHash != headers[index - 1].ComputeHash())
            {
                linkageValid = false;
                break;
            }
        }

        if (!linkageValid)
        {
            throw new InvalidDataException("The headers candidate contains a broken previous-block linkage.");
        }

        return new HeadersEvidence(
            payload.LongLength,
            Convert.ToHexStringLower(SHA256.HashData(payload)),
            nameof(HeadersPayloadCodec),
            count,
            count == 0 ? null : headers[0].ComputeHash().ToDisplayHex(),
            count == 0 ? null : headers[count - 1].ComputeHash().ToDisplayHex(),
            linkageValid);
    }

    internal async Task PublishAsync(ProbeManifest manifest, CancellationToken cancellationToken)
    {
        if (_published)
        {
            throw new InvalidOperationException("The candidate has already been published.");
        }

        var stream = _stream ?? throw new ObjectDisposedException(nameof(CandidateArtifact));
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        stream.Flush(flushToDisk: true);
        await stream.DisposeAsync().ConfigureAwait(false);
        _stream = null;

        var manifestPartPath = Path.Combine(_stagingDirectory, "candidate.json.part");
        await using (var manifestStream = new FileStream(
            manifestPartPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            ProbeTransport.BufferLength,
            FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            await JsonSerializer.SerializeAsync(manifestStream, manifest, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            await manifestStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            manifestStream.Flush(flushToDisk: true);
        }

        File.Move(_partPath, Path.Combine(_stagingDirectory, "candidate.bin"));
        File.Move(manifestPartPath, Path.Combine(_stagingDirectory, "candidate.json"));
        Directory.Move(_stagingDirectory, _outputDirectory);
        _published = true;
    }

    public async ValueTask DisposeAsync()
    {
        if (_stream is not null)
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
            _stream = null;
        }
    }
}
