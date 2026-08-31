using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Messages;

/// <summary>
/// Provides a zero-copy view over a reject payload. The borrowed spans remain valid only while
/// the source storage is stable and has not been returned to a pool or otherwise reused.
/// </summary>
public readonly ref struct RejectPayload
{
    internal RejectPayload(
        ReadOnlySpan<byte> command,
        byte code,
        ReadOnlySpan<byte> reason,
        ReadOnlySpan<byte> data)
    {
        Command = command;
        Code = code;
        Reason = reason;
        Data = data;
    }

    /// <summary>Gets the borrowed raw command bytes.</summary>
    public ReadOnlySpan<byte> Command { get; }

    public byte Code { get; }

    /// <summary>Gets the borrowed raw reason bytes.</summary>
    public ReadOnlySpan<byte> Reason { get; }

    /// <summary>Gets the borrowed command-specific data bytes.</summary>
    public ReadOnlySpan<byte> Data { get; }

    public bool TryGetObjectHash(out Hash256 hash)
    {
        hash = default;
        if ((!Command.SequenceEqual("tx"u8) && !Command.SequenceEqual("block"u8)) ||
            Data.Length != Hash256.Length)
        {
            return false;
        }

        return Hash256.TryCreate(Data, out hash) == System.Buffers.OperationStatus.Done;
    }
}
