using System.Buffers;
using System.Buffers.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Tests.Protocol.Wire;

[TestClass]
public sealed class MessageHeaderCodecTests
{
    private const ulong MinimumExtendedPayloadLength = (ulong)uint.MaxValue + 1;

    private static ReadOnlySpan<byte> MainnetMagic => [0xe3, 0xe1, 0xf3, 0xe8];

    [TestMethod]
    public void BasicHeaderRoundTripsAndExposesChecksumBytes()
    {
        ReadOnlySpan<byte> checksum = [0x11, 0x22, 0x33, 0x44];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic("version"u8, 85, checksum, out var original));
        Span<byte> encoded = stackalloc byte[MessageHeaderCodec.BasicHeaderLength];

        var writeStatus = MessageHeaderCodec.TryWrite(
            encoded,
            MainnetMagic,
            original,
            1_000_000,
            out var bytesWritten);
        var parseStatus = MessageHeaderCodec.TryParse(
            encoded,
            MainnetMagic,
            1_000_000,
            out var parsed,
            out var bytesConsumed);

        Assert.AreEqual(OperationStatus.Done, writeStatus);
        Assert.AreEqual(MessageHeaderCodec.BasicHeaderLength, bytesWritten);
        CollectionAssert.AreEqual(
            new byte[]
            {
                0xe3, 0xe1, 0xf3, 0xe8,
                (byte)'v', (byte)'e', (byte)'r', (byte)'s', (byte)'i', (byte)'o', (byte)'n', 0, 0, 0, 0, 0,
                85, 0, 0, 0,
                0x11, 0x22, 0x33, 0x44,
            },
            encoded.ToArray());
        Assert.AreEqual(OperationStatus.Done, parseStatus);
        Assert.AreEqual(MessageHeaderCodec.BasicHeaderLength, bytesConsumed);
        Assert.AreEqual(original, parsed);
        Assert.IsTrue(parsed.Command.Equals("version"u8));
        Assert.AreEqual(0x11, parsed.PayloadChecksum.Byte0);
        Assert.AreEqual(0x22, parsed.PayloadChecksum.Byte1);
        Assert.AreEqual(0x33, parsed.PayloadChecksum.Byte2);
        Assert.AreEqual(0x44, parsed.PayloadChecksum.Byte3);

        Span<byte> commandDestination = stackalloc byte[7];
        Assert.AreEqual(
            OperationStatus.Done,
            parsed.Command.TryCopyTo(commandDestination, out var commandBytesWritten));
        Assert.AreEqual(7, commandBytesWritten);
        Assert.IsTrue(commandDestination.SequenceEqual("version"u8));

        Span<byte> checksumDestination = stackalloc byte[4];
        Assert.AreEqual(
            OperationStatus.Done,
            parsed.PayloadChecksum.TryCopyTo(checksumDestination, out var checksumBytesWritten));
        Assert.AreEqual(4, checksumBytesWritten);
        Assert.IsTrue(checksumDestination.SequenceEqual(checksum));
    }

    [TestMethod]
    public void ExtendedHeaderRoundTripsWithSentinelAndZeroChecksum()
    {
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateExtended("block"u8, MinimumExtendedPayloadLength, out var original));
        Span<byte> encoded = stackalloc byte[MessageHeaderCodec.ExtendedHeaderLength];

        var writeStatus = MessageHeaderCodec.TryWrite(
            encoded,
            MainnetMagic,
            original,
            MinimumExtendedPayloadLength,
            out var bytesWritten);
        var parseStatus = MessageHeaderCodec.TryParse(
            encoded,
            MainnetMagic,
            MinimumExtendedPayloadLength,
            out var parsed,
            out var bytesConsumed);

        Assert.AreEqual(OperationStatus.Done, writeStatus);
        Assert.AreEqual(MessageHeaderCodec.ExtendedHeaderLength, bytesWritten);
        Assert.IsTrue(encoded.Slice(4, 12).SequenceEqual("extmsg\0\0\0\0\0\0"u8));
        Assert.AreEqual(uint.MaxValue, BinaryPrimitives.ReadUInt32LittleEndian(encoded.Slice(16, 4)));
        Assert.IsTrue(encoded.Slice(20, 4).SequenceEqual(stackalloc byte[4]));
        Assert.IsTrue(encoded.Slice(24, 12).SequenceEqual("block\0\0\0\0\0\0\0"u8));
        Assert.AreEqual(MinimumExtendedPayloadLength, BinaryPrimitives.ReadUInt64LittleEndian(encoded[36..]));
        Assert.AreEqual(OperationStatus.Done, parseStatus);
        Assert.AreEqual(MessageHeaderCodec.ExtendedHeaderLength, bytesConsumed);
        Assert.AreEqual(original, parsed);
        Assert.AreEqual(MessageChecksum.Zero, parsed.PayloadChecksum);
    }

    [TestMethod]
    public void ParseReportsNeedMoreDataAtEveryBasicBoundary()
    {
        Span<byte> encoded = stackalloc byte[MessageHeaderCodec.BasicHeaderLength];
        CreateAndWriteBasic(encoded);

        for (var length = 0; length < MessageHeaderCodec.BasicHeaderLength; length++)
        {
            var status = MessageHeaderCodec.TryParse(
                encoded[..length],
                MainnetMagic,
                1_000_000,
                out _,
                out var bytesConsumed);

            Assert.AreEqual(OperationStatus.NeedMoreData, status, $"Length {length}");
            Assert.AreEqual(0, bytesConsumed, $"Length {length}");
        }
    }

    [TestMethod]
    public void ParseReportsNeedMoreDataAtEveryExtendedBoundaryAfterBasicHeader()
    {
        Span<byte> encoded = stackalloc byte[MessageHeaderCodec.ExtendedHeaderLength];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateExtended("block"u8, MinimumExtendedPayloadLength, out var header));
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(
                encoded,
                MainnetMagic,
                header,
                MinimumExtendedPayloadLength,
                out _));

        for (var length = MessageHeaderCodec.BasicHeaderLength;
             length < MessageHeaderCodec.ExtendedHeaderLength;
             length++)
        {
            var status = MessageHeaderCodec.TryParse(
                encoded[..length],
                MainnetMagic,
                MinimumExtendedPayloadLength,
                out _,
                out var bytesConsumed);

            Assert.AreEqual(OperationStatus.NeedMoreData, status, $"Length {length}");
            Assert.AreEqual(0, bytesConsumed, $"Length {length}");
        }
    }

    [TestMethod]
    public void ParseRejectsWrongMagicAndNonCanonicalCommands()
    {
        Span<byte> encoded = stackalloc byte[MessageHeaderCodec.BasicHeaderLength];
        CreateAndWriteBasic(encoded);

        encoded[0] ^= 0xff;
        AssertInvalid(encoded);
        encoded[0] ^= 0xff;

        encoded[4] = 0x1f;
        AssertInvalid(encoded);
        encoded[4] = (byte)'p';

        encoded[4] = 0x7f;
        AssertInvalid(encoded);
        encoded[4] = (byte)'p';

        encoded[5] = 0;
        encoded[6] = (byte)'x';
        AssertInvalid(encoded);
    }

    [TestMethod]
    public void ParseAcceptsEmptyAndTwelveCharacterCommands()
    {
        Span<byte> empty = stackalloc byte[MessageHeaderCodec.BasicHeaderLength];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic([], 0, [0, 0, 0, 0], out var emptyHeader));
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(empty, MainnetMagic, emptyHeader, 0, out _));
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryParse(empty, MainnetMagic, 0, out var parsedEmpty, out _));
        Assert.AreEqual(0, parsedEmpty.Command.Length);

        Span<byte> full = stackalloc byte[MessageHeaderCodec.BasicHeaderLength];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic("123456789012"u8, 0, [0, 0, 0, 0], out var fullHeader));
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(full, MainnetMagic, fullHeader, 0, out _));
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryParse(full, MainnetMagic, 0, out var parsedFull, out _));
        Assert.IsTrue(parsedFull.Command.Equals("123456789012"u8));
    }

    [TestMethod]
    public void ShortCommandsHaveDeterministicZeroPaddingAndEquality()
    {
        Assert.AreEqual(
            OperationStatus.Done,
            MessageCommand.TryCreate("123456789012"u8, out _));
        Assert.AreEqual(
            OperationStatus.Done,
            MessageCommand.TryCreate("ping"u8, out var first));
        Assert.AreEqual(
            OperationStatus.Done,
            MessageCommand.TryCreate("ping"u8, out var second));

        Assert.AreEqual(first, second);
        Assert.AreEqual(first.GetHashCode(), second.GetHashCode());
        Assert.AreEqual(4, first.Length);
        Assert.IsTrue(first.Equals("ping"u8));

        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic("ping"u8, 0, [0, 0, 0, 0], out var header));
        Span<byte> encoded = stackalloc byte[MessageHeaderCodec.BasicHeaderLength];
        encoded.Fill(0xaa);
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(encoded, MainnetMagic, header, 0, out _));
        Assert.IsTrue(encoded.Slice(4, 12).SequenceEqual("ping\0\0\0\0\0\0\0\0"u8));
    }

    [TestMethod]
    public void ParseRejectsMalformedExtendedSentinelFields()
    {
        Span<byte> encoded = stackalloc byte[MessageHeaderCodec.ExtendedHeaderLength];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateExtended("block"u8, MinimumExtendedPayloadLength, out var header));
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(
                encoded,
                MainnetMagic,
                header,
                MinimumExtendedPayloadLength,
                out _));

        encoded[16] = 0xfe;
        AssertInvalid(encoded);
        encoded[16] = 0xff;

        encoded[20] = 1;
        AssertInvalid(encoded);
        encoded[20] = 0;

        encoded[29] = 0;
        encoded[30] = (byte)'x';
        AssertInvalid(encoded);
    }

    [TestMethod]
    public void ExtendedHeaderRejectsPayloadAtBasicMaximum()
    {
        Assert.AreEqual(
            OperationStatus.InvalidData,
            MessageHeader.TryCreateExtended("block"u8, uint.MaxValue, out _));

        Span<byte> encoded = stackalloc byte[MessageHeaderCodec.ExtendedHeaderLength];
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateExtended("block"u8, MinimumExtendedPayloadLength, out var header));
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(
                encoded,
                MainnetMagic,
                header,
                MinimumExtendedPayloadLength,
                out _));

        BinaryPrimitives.WriteUInt64LittleEndian(encoded[36..], uint.MaxValue);
        AssertInvalid(encoded);
    }

    [TestMethod]
    public void BasicHeaderAcceptsPayloadAtBasicMaximum()
    {
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic("block"u8, uint.MaxValue, [1, 2, 3, 4], out var header));
        Span<byte> encoded = stackalloc byte[MessageHeaderCodec.BasicHeaderLength];

        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(encoded, MainnetMagic, header, uint.MaxValue, out var bytesWritten));
        Assert.AreEqual(MessageHeaderCodec.BasicHeaderLength, bytesWritten);
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryParse(
                encoded,
                MainnetMagic,
                uint.MaxValue,
                out var parsed,
                out var bytesConsumed));
        Assert.AreEqual(MessageHeaderCodec.BasicHeaderLength, bytesConsumed);
        Assert.AreEqual(MessageHeaderFormat.Basic, parsed.Format);
        Assert.AreEqual((ulong)uint.MaxValue, parsed.PayloadLength);
    }

    [TestMethod]
    public void ParseRejectsPayloadLengthAboveCallerMaximum()
    {
        Span<byte> basic = stackalloc byte[MessageHeaderCodec.BasicHeaderLength];
        CreateAndWriteBasic(basic, payloadLength: 101, maximumPayloadLength: 101);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            MessageHeaderCodec.TryParse(basic, MainnetMagic, 100, out _, out _));

        Span<byte> extended = stackalloc byte[MessageHeaderCodec.ExtendedHeaderLength];
        const ulong extendedPayloadLength = MinimumExtendedPayloadLength + 1;
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateExtended("block"u8, extendedPayloadLength, out var header));
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(extended, MainnetMagic, header, extendedPayloadLength, out _));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            MessageHeaderCodec.TryParse(
                extended,
                MainnetMagic,
                MinimumExtendedPayloadLength,
                out _,
                out _));
    }

    [TestMethod]
    public void WriteReportsDestinationTooSmallAtEveryBoundary()
    {
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic("ping"u8, 8, [1, 2, 3, 4], out var basic));
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateExtended("block"u8, MinimumExtendedPayloadLength, out var extended));
        Span<byte> destination = stackalloc byte[MessageHeaderCodec.ExtendedHeaderLength];

        for (var length = 0; length < MessageHeaderCodec.BasicHeaderLength; length++)
        {
            destination.Fill(0xaa);
            var status = MessageHeaderCodec.TryWrite(
                destination[..length], MainnetMagic, basic, 100, out var bytesWritten);
            Assert.AreEqual(OperationStatus.DestinationTooSmall, status, $"Basic length {length}");
            Assert.AreEqual(0, bytesWritten, $"Basic length {length}");
            Assert.IsTrue(IsFilledWith(destination, 0xaa), $"Basic length {length}");
        }

        for (var length = 0; length < MessageHeaderCodec.ExtendedHeaderLength; length++)
        {
            destination.Fill(0xaa);
            var status = MessageHeaderCodec.TryWrite(
                destination[..length],
                MainnetMagic,
                extended,
                MinimumExtendedPayloadLength,
                out var bytesWritten);
            Assert.AreEqual(OperationStatus.DestinationTooSmall, status, $"Extended length {length}");
            Assert.AreEqual(0, bytesWritten, $"Extended length {length}");
            Assert.IsTrue(IsFilledWith(destination, 0xaa), $"Extended length {length}");
        }
    }

    [TestMethod]
    public void FactoriesAndWriteRejectInvalidInputs()
    {
        Assert.AreEqual(
            OperationStatus.InvalidData,
            MessageHeader.TryCreateBasic("thirteen-byte!"u8, 0, [0, 0, 0, 0], out _));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            MessageHeader.TryCreateBasic([0x1f], 0, [0, 0, 0, 0], out _));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            MessageHeader.TryCreateBasic("ping"u8, 0, [0, 0, 0], out _));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            MessageHeader.TryCreateBasic("extmsg"u8, 0, [0, 0, 0, 0], out _));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            MessageHeader.TryCreateExtended("block"u8, uint.MaxValue, out _));

        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic("ping"u8, 8, [1, 2, 3, 4], out var header));
        Span<byte> destination = stackalloc byte[MessageHeaderCodec.BasicHeaderLength];
        destination.Fill(0xaa);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            MessageHeaderCodec.TryWrite(destination, [1, 2, 3], header, 8, out _));
        Assert.IsTrue(IsFilledWith(destination, 0xaa));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            MessageHeaderCodec.TryWrite(destination, MainnetMagic, header, 7, out _));
        Assert.IsTrue(IsFilledWith(destination, 0xaa));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            MessageHeaderCodec.TryParse(destination, [1, 2, 3], 8, out _, out _));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            MessageHeaderCodec.TryWrite(destination, MainnetMagic, default, 8, out var defaultBytesWritten));
        Assert.AreEqual(0, defaultBytesWritten);
        Assert.IsTrue(IsFilledWith(destination, 0xaa));
        Assert.AreEqual(MessageHeaderFormat.Unknown, default(MessageHeader).Format);
        Assert.AreEqual(0, default(MessageHeader).EncodedLength);
    }

    [TestMethod]
    public void ParseAndWriteDoNotAllocate()
    {
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic("ping"u8, 8, [1, 2, 3, 4], out var header));
        Span<byte> destination = stackalloc byte[MessageHeaderCodec.BasicHeaderLength];

        _ = MessageHeaderCodec.TryWrite(destination, MainnetMagic, header, 8, out _);
        _ = MessageHeaderCodec.TryParse(destination, MainnetMagic, 8, out _, out _);
        var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();

        var writeStatus = MessageHeaderCodec.TryWrite(destination, MainnetMagic, header, 8, out _);
        var parseStatus = MessageHeaderCodec.TryParse(destination, MainnetMagic, 8, out _, out _);

        var allocatedAfter = GC.GetAllocatedBytesForCurrentThread();
        Assert.AreEqual(OperationStatus.Done, writeStatus);
        Assert.AreEqual(OperationStatus.Done, parseStatus);
        Assert.AreEqual(allocatedBefore, allocatedAfter);
    }

    private static void CreateAndWriteBasic(
        Span<byte> destination,
        uint payloadLength = 8,
        ulong maximumPayloadLength = 1_000_000)
    {
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic("ping"u8, payloadLength, [1, 2, 3, 4], out var header));
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryWrite(destination, MainnetMagic, header, maximumPayloadLength, out _));
    }

    private static void AssertInvalid(ReadOnlySpan<byte> encoded)
    {
        var status = MessageHeaderCodec.TryParse(
            encoded,
            MainnetMagic,
            ulong.MaxValue,
            out _,
            out var bytesConsumed);

        Assert.AreEqual(OperationStatus.InvalidData, status);
        Assert.AreEqual(0, bytesConsumed);
    }

    private static bool IsFilledWith(ReadOnlySpan<byte> value, byte expected)
    {
        foreach (var item in value)
        {
            if (item != expected)
            {
                return false;
            }
        }

        return true;
    }
}
