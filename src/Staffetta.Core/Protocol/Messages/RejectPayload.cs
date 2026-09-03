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

    /// <summary>Gets the peer's raw rejection code without interpreting or validating it.</summary>
    public byte Code { get; }

    /// <summary>Gets the borrowed raw reason bytes.</summary>
    public ReadOnlySpan<byte> Reason { get; }

    /// <summary>Gets the borrowed command-specific data bytes.</summary>
    public ReadOnlySpan<byte> Data { get; }

    /// <summary>Copies the object hash for an exact lowercase tx or block command with 32 data bytes.</summary>
    /// <param name="hash">The wire-order object identifier on success; otherwise the default value.</param>
    /// <returns>Whether the command and data have the supported object-hash shape.</returns>
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
