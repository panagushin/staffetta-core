using System.Buffers;
using System.Buffers.Binary;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Blocks;

public static class BlockHeaderCodec
{
    public const int EncodedLength = 80;

    private const int VersionOffset = 0;
    private const int PreviousBlockHashOffset = VersionOffset + sizeof(int);
    private const int MerkleRootOffset = PreviousBlockHashOffset + Hash256.Length;
    private const int TimestampOffset = MerkleRootOffset + Hash256.Length;
    private const int BitsOffset = TimestampOffset + sizeof(uint);
    private const int NonceOffset = BitsOffset + sizeof(uint);

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
