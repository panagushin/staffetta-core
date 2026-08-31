using System.Text.Json.Serialization;

namespace Staffetta.Bsv.LiveProbe;

internal sealed record ProbeManifest(
    [property: JsonPropertyOrder(0)] int Schema,
    [property: JsonPropertyOrder(1)] string RepositoryCommit,
    [property: JsonPropertyOrder(2)] string RepositoryState,
    [property: JsonPropertyOrder(3)] string Runtime,
    [property: JsonPropertyOrder(4)] string OperatingSystem,
    [property: JsonPropertyOrder(5)] string ConfiguredRemote,
    [property: JsonPropertyOrder(6)] string ResolvedRemote,
    [property: JsonPropertyOrder(7)] DateTimeOffset StartedUtc,
    [property: JsonPropertyOrder(8)] DateTimeOffset CompletedUtc,
    [property: JsonPropertyOrder(9)] IReadOnlyDictionary<string, long> DurationMilliseconds,
    [property: JsonPropertyOrder(10)] int PeerProtocolVersion,
    [property: JsonPropertyOrder(11)] PeerUserAgent PeerUserAgent,
    [property: JsonPropertyOrder(12)] string Locator,
    [property: JsonPropertyOrder(13)] long ObservedCommandCount,
    [property: JsonPropertyOrder(14)] bool ObservedCommandsTruncated,
    [property: JsonPropertyOrder(15)] IReadOnlyList<string> ObservedCommands,
    [property: JsonPropertyOrder(16)] N2Observations N2,
    [property: JsonPropertyOrder(17)] HeadersEvidence Headers,
    [property: JsonPropertyOrder(18)] IReadOnlyDictionary<string, string> StimulusClasses);

internal sealed record PeerUserAgent(
    [property: JsonPropertyOrder(0)] string? SafeAscii,
    [property: JsonPropertyOrder(1)] int Length,
    [property: JsonPropertyOrder(2)] string Sha256);

internal sealed record N2Observations(
    [property: JsonPropertyOrder(0)] string RelayByte,
    [property: JsonPropertyOrder(1)] string DuplicateVerack,
    [property: JsonPropertyOrder(2)] string BadMagicResync,
    [property: JsonPropertyOrder(3)] string HeadersExactLength,
    [property: JsonPropertyOrder(4)] string PingPongExactLength);

internal sealed record HeadersEvidence(
    [property: JsonPropertyOrder(0)] long PayloadLength,
    [property: JsonPropertyOrder(1)] string Sha256,
    [property: JsonPropertyOrder(2)] string Parser,
    [property: JsonPropertyOrder(3)] int Count,
    [property: JsonPropertyOrder(4)] string? FirstBlockId,
    [property: JsonPropertyOrder(5)] string? LastBlockId,
    [property: JsonPropertyOrder(6)] bool LinkageValid);
