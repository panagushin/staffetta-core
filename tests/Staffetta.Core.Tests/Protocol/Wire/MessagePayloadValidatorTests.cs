using System.Buffers;
using System.Buffers.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Wire;

namespace Staffetta.Core.Tests.Protocol.Wire;

[TestClass]
public sealed class MessagePayloadValidatorTests
{
    private static readonly byte[] Payload = Enumerable.Range(0, 257)
        .Select(value => (byte)value)
        .ToArray();

    [TestMethod]
    public void BasicPayloadValidatesWholeByteWiseAndAtEverySplit()
    {
        AssertValidBasic([Payload]);
        AssertValidBasic(Payload.Select(value => new[] { value }).ToArray());

        for (var split = 1; split < Payload.Length; split++)
        {
            AssertValidBasic([Payload[..split], Payload[split..]]);
        }
    }

    [TestMethod]
    public void BasicPayloadRejectsWrongChecksumAfterConsumingDeclaredLength()
    {
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic(
                "tx"u8,
                (uint)Payload.Length,
                [0, 0, 0, 0],
                out var header));
        using var validator = CreateValidator(header);

        Assert.AreEqual(
            OperationStatus.InvalidData,
            validator.Consume(Payload, out var bytesConsumed));
        Assert.AreEqual(Payload.Length, bytesConsumed);
        Assert.IsTrue(validator.IsCompleted);
        Assert.AreEqual<ulong>(0, validator.RemainingLength);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            validator.TryGetPayloadDoubleSha256(out _));
    }

    [TestMethod]
    public void ConsumeTakesOnlyDeclaredPayloadAndLeavesFollowingBytesUntouched()
    {
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic(
                "tx"u8,
                (uint)Payload.Length,
                GetChecksumBytes(Payload),
                out var header));
        using var validator = CreateValidator(header);
        var source = new byte[Payload.Length + MessageHeaderCodec.BasicHeaderLength];
        Payload.CopyTo(source, 0);
        Array.Fill(source, (byte)0xa5, Payload.Length, MessageHeaderCodec.BasicHeaderLength);

        Assert.AreEqual(
            OperationStatus.Done,
            validator.Consume(source, out var bytesConsumed));
        Assert.AreEqual(Payload.Length, bytesConsumed);
        Assert.IsTrue(source.AsSpan(bytesConsumed).IndexOfAnyExcept((byte)0xa5) < 0);
    }

    [TestMethod]
    public void TruncatedPayloadRemainsIncompleteWithoutGuessing()
    {
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic(
                "tx"u8,
                (uint)Payload.Length,
                GetChecksumBytes(Payload),
                out var header));
        using var validator = CreateValidator(header);

        Assert.AreEqual(
            OperationStatus.NeedMoreData,
            validator.Consume(Payload.AsSpan(0, Payload.Length - 1), out var bytesConsumed));
        Assert.AreEqual(Payload.Length - 1, bytesConsumed);
        Assert.IsFalse(validator.IsCompleted);
        Assert.AreEqual<ulong>(1, validator.RemainingLength);
    }

    [TestMethod]
    public void BasicAndExtendedPayloadsCompleteAtTheirDeclaredLength()
    {
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic("verack"u8, 0, GetChecksumBytes([]), out var basicHeader));
        using var basicValidator = CreateValidator(basicHeader);
        Assert.AreEqual(
            OperationStatus.Done,
            basicValidator.Consume([], out var basicBytesConsumed));
        Assert.AreEqual(0, basicBytesConsumed);
        Assert.IsTrue(basicValidator.IsCompleted);
        Assert.AreEqual(
            OperationStatus.Done,
            basicValidator.TryGetPayloadDoubleSha256(out var basicHash));
        Assert.AreEqual(Hash256.DoubleSha256([]), basicHash);

        var extendedHeader = ParseInboundExtendedHeader((ulong)Payload.Length);
        using var extendedValidator = CreateValidator(extendedHeader);
        Assert.AreEqual(
            OperationStatus.Done,
            extendedValidator.Consume(Payload, out var extendedBytesConsumed));
        Assert.AreEqual(Payload.Length, extendedBytesConsumed);
        Assert.IsTrue(extendedValidator.IsCompleted);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            extendedValidator.TryGetPayloadDoubleSha256(out _));

        Assert.AreEqual(
            OperationStatus.Done,
            MessagePayloadValidator.TryCreate(
                extendedHeader,
                computeExtendedDoubleSha256: true,
                out var hashingExtendedValidator));
        Assert.IsNotNull(hashingExtendedValidator);
        using (hashingExtendedValidator)
        {
            Assert.AreEqual(
                OperationStatus.Done,
                hashingExtendedValidator.Consume(Payload, out var hashingBytesConsumed));
            Assert.AreEqual(Payload.Length, hashingBytesConsumed);
            Assert.AreEqual(
                OperationStatus.Done,
                hashingExtendedValidator.TryGetPayloadDoubleSha256(out var extendedHash));
            Assert.AreEqual(Hash256.DoubleSha256(Payload), extendedHash);
        }
    }

    [TestMethod]
    public void ValidatorCannotBeCreatedFromDefaultHeaderOrConsumedTwice()
    {
        Assert.AreEqual(
            OperationStatus.InvalidData,
            MessagePayloadValidator.TryCreate(default, out var invalidValidator));
        Assert.IsNull(invalidValidator);

        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic("verack"u8, 0, GetChecksumBytes([]), out var header));
        using var validator = CreateValidator(header);
        Assert.AreEqual(OperationStatus.Done, validator.Consume([], out _));
        Assert.AreEqual(OperationStatus.InvalidData, validator.Consume([], out var bytesConsumed));
        Assert.AreEqual(0, bytesConsumed);
    }

    private static void AssertValidBasic(byte[][] chunks)
    {
        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeader.TryCreateBasic(
                "tx"u8,
                (uint)Payload.Length,
                GetChecksumBytes(Payload),
                out var header));
        using var validator = CreateValidator(header);

        for (var index = 0; index < chunks.Length; index++)
        {
            var expectedStatus = index == chunks.Length - 1
                ? OperationStatus.Done
                : OperationStatus.NeedMoreData;
            Assert.AreEqual(
                expectedStatus,
                validator.Consume(chunks[index], out var bytesConsumed),
                $"Chunk {index}");
            Assert.AreEqual(chunks[index].Length, bytesConsumed, $"Chunk {index}");
        }

        Assert.IsTrue(validator.IsCompleted);
        Assert.AreEqual<ulong>(0, validator.RemainingLength);
        Assert.AreEqual(
            OperationStatus.Done,
            validator.TryGetPayloadDoubleSha256(out var payloadHash));
        Assert.AreEqual(Hash256.DoubleSha256(Payload), payloadHash);
    }

    private static MessagePayloadValidator CreateValidator(in MessageHeader header)
    {
        Assert.AreEqual(
            OperationStatus.Done,
            MessagePayloadValidator.TryCreate(header, out var validator));
        Assert.IsNotNull(validator);
        return validator;
    }

    private static byte[] GetChecksumBytes(ReadOnlySpan<byte> payload)
    {
        var checksum = MessageChecksum.Compute(payload);
        var bytes = new byte[MessageChecksum.Length];
        Assert.AreEqual(
            OperationStatus.Done,
            checksum.TryCopyTo(bytes, out var bytesWritten));
        Assert.AreEqual(MessageChecksum.Length, bytesWritten);
        return bytes;
    }

    private static MessageHeader ParseInboundExtendedHeader(ulong payloadLength)
    {
        Span<byte> encoded = stackalloc byte[MessageHeaderCodec.ExtendedHeaderLength];
        encoded.Clear();
        ReadOnlySpan<byte> networkMagic = [0xe3, 0xe1, 0xf3, 0xe8];
        networkMagic.CopyTo(encoded);
        MessageHeaderCodec.ExtendedCommand.CopyTo(encoded[4..]);
        BinaryPrimitives.WriteUInt32LittleEndian(encoded[16..], uint.MaxValue);
        "tx"u8.CopyTo(encoded[24..]);
        BinaryPrimitives.WriteUInt64LittleEndian(encoded[36..], payloadLength);

        Assert.AreEqual(
            OperationStatus.Done,
            MessageHeaderCodec.TryParse(
                encoded,
                networkMagic,
                payloadLength,
                out var header,
                out var bytesConsumed));
        Assert.AreEqual(MessageHeaderCodec.ExtendedHeaderLength, bytesConsumed);
        return header;
    }
}
