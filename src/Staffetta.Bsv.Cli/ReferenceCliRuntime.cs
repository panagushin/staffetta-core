using System.Security.Cryptography;

namespace Staffetta.Bsv.Cli;

internal interface IReferenceCliRuntime
{
    long GetUnixTimeSeconds();

    ulong CreateNonce();

    Task DelayAsync(TimeSpan duration, CancellationToken cancellationToken);
}

internal sealed class SystemReferenceCliRuntime : IReferenceCliRuntime
{
    internal static SystemReferenceCliRuntime Instance { get; } = new();

    public long GetUnixTimeSeconds() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    public ulong CreateNonce()
    {
        Span<byte> bytes = stackalloc byte[sizeof(ulong)];
        RandomNumberGenerator.Fill(bytes);
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(bytes);
    }

    public Task DelayAsync(TimeSpan duration, CancellationToken cancellationToken) =>
        Task.Delay(duration, cancellationToken);
}
