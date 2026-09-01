using System.Buffers.Binary;

namespace Staffetta.Bsv.Cli.Tests;

internal static class TransactionFixture
{
    internal static byte[] CreateMinimal(long outputValueSatoshis = 1)
    {
        var transaction = new byte[60];
        BinaryPrimitives.WriteInt32LittleEndian(transaction, 1);
        transaction[4] = 1;
        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(37), uint.MaxValue);
        BinaryPrimitives.WriteUInt32LittleEndian(transaction.AsSpan(42), uint.MaxValue);
        transaction[46] = 1;
        BinaryPrimitives.WriteInt64LittleEndian(transaction.AsSpan(47), outputValueSatoshis);
        return transaction;
    }

    internal static async ValueTask<string> WriteTempAsync(
        int outputScriptLength = 0,
        ReadOnlyMemory<byte> trailing = default,
        long outputValueSatoshis = 1)
    {
        var path = Path.Combine(Path.GetTempPath(), $"staffetta-cli-{Guid.NewGuid():N}.bin");
        await using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        var prefix = new byte[55];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, 1);
        prefix[4] = 1;
        BinaryPrimitives.WriteUInt32LittleEndian(prefix.AsSpan(37), uint.MaxValue);
        BinaryPrimitives.WriteUInt32LittleEndian(prefix.AsSpan(42), uint.MaxValue);
        prefix[46] = 1;
        BinaryPrimitives.WriteInt64LittleEndian(prefix.AsSpan(47), outputValueSatoshis);
        await stream.WriteAsync(prefix);
        WriteCompactSize(stream, (ulong)outputScriptLength);
        var scriptChunk = new byte[8192];
        Array.Fill(scriptChunk, (byte)0x51);
        for (var remaining = outputScriptLength; remaining > 0;)
        {
            var count = Math.Min(remaining, scriptChunk.Length);
            await stream.WriteAsync(scriptChunk.AsMemory(0, count));
            remaining -= count;
        }

        await stream.WriteAsync(new byte[4]);
        if (!trailing.IsEmpty)
        {
            await stream.WriteAsync(trailing);
        }

        return path;
    }

    private static void WriteCompactSize(Stream stream, ulong value)
    {
        Span<byte> encoded = stackalloc byte[9];
        int length;
        if (value < 0xfd)
        {
            encoded[0] = (byte)value;
            length = 1;
        }
        else if (value <= ushort.MaxValue)
        {
            encoded[0] = 0xfd;
            BinaryPrimitives.WriteUInt16LittleEndian(encoded[1..], (ushort)value);
            length = 3;
        }
        else
        {
            encoded[0] = 0xfe;
            BinaryPrimitives.WriteUInt32LittleEndian(encoded[1..], checked((uint)value));
            length = 5;
        }

        stream.Write(encoded[..length]);
    }
}
