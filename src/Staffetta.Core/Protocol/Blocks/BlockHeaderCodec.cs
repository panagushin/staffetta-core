using System.Buffers;
using System.Buffers.Binary;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

/// <summary>Encodes and decodes fixed-width block headers without consensus or chain-context validation.</summary>
public static class BlockHeaderCodec
{
    /// <summary>The serialized header length in bytes.</summary>
    public const int EncodedLength = 80;

    private const int VersionOffset = 0;
    private const int PreviousBlockHashOffset = VersionOffset + sizeof(int);
    private const int MerkleRootOffset = PreviousBlockHashOffset + Hash256.Length;
    private const int TimestampOffset = MerkleRootOffset + Hash256.Length;
    private const int BitsOffset = TimestampOffset + sizeof(uint);
    private const int NonceOffset = BitsOffset + sizeof(uint);

    /// <summary>Copies one header from the beginning of the source, preserving hash wire order.</summary>
    /// <param name="source">Bytes beginning at a header; trailing bytes are allowed.</param>
    /// <param name="header">The decoded header on success; otherwise the default value.</param>
    /// <param name="bytesConsumed">80 on success; otherwise zero.</param>
    /// <returns><see cref="OperationStatus.Done"/> or <see cref="OperationStatus.NeedMoreData"/>.</returns>
    public static OperationStatus TryParse(
        ReadOnlySpan<byte> source,
        out BlockHeader header,
        out int bytesConsumed)
    {
        header = default;
        bytesConsumed = 0;
        if (source.Length < EncodedLength)
        {
            return OperationStatus.NeedMoreData;
        }

        header = new BlockHeader(
            BinaryPrimitives.ReadInt32LittleEndian(source[VersionOffset..]),
            Hash256.FromWireBytes(source.Slice(PreviousBlockHashOffset, Hash256.Length)),
            Hash256.FromWireBytes(source.Slice(MerkleRootOffset, Hash256.Length)),
            BinaryPrimitives.ReadUInt32LittleEndian(source[TimestampOffset..]),
            BinaryPrimitives.ReadUInt32LittleEndian(source[BitsOffset..]),
            BinaryPrimitives.ReadUInt32LittleEndian(source[NonceOffset..]));
        bytesConsumed = EncodedLength;
        return OperationStatus.Done;
    }

    /// <summary>Writes one header, leaving an undersized destination unchanged.</summary>
    /// <param name="destination">Storage for at least 80 bytes; trailing bytes are untouched.</param>
    /// <param name="header">The fields to serialize without validity checks.</param>
    /// <param name="bytesWritten">80 on success; otherwise zero.</param>
    /// <returns><see cref="OperationStatus.Done"/> or <see cref="OperationStatus.DestinationTooSmall"/>.</returns>
    public static OperationStatus TryWrite(
        Span<byte> destination,
        in BlockHeader header,
        out int bytesWritten)
    {
        bytesWritten = 0;
        if (destination.Length < EncodedLength)
        {
            return OperationStatus.DestinationTooSmall;
        }

        WriteUnchecked(destination, header);
        bytesWritten = EncodedLength;
        return OperationStatus.Done;
    }

    internal static void WriteUnchecked(Span<byte> destination, in BlockHeader header)
    {
        BinaryPrimitives.WriteInt32LittleEndian(destination[VersionOffset..], header.Version);
        header.PreviousBlockHash.WriteWireBytesTo(destination.Slice(PreviousBlockHashOffset, Hash256.Length));
        header.MerkleRoot.WriteWireBytesTo(destination.Slice(MerkleRootOffset, Hash256.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(destination[TimestampOffset..], header.Timestamp);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[BitsOffset..], header.Bits);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[NonceOffset..], header.Nonce);
    }
}
