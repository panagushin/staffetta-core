using System.Buffers;
using System.Buffers.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Handshake;

namespace Staffetta.Core.Tests.Protocol.Handshake;

[TestClass]
public sealed class ProtoconfPayloadCodecTests
{
    private const uint ReceiveLimit = 64 * 1024 * 1024;

    [TestMethod]
    public void WriterEmitsCanonicalTwoFieldDefaultPolicy()
    {
        Span<byte> encoded = stackalloc byte[32];
        Assert.AreEqual(
            OperationStatus.Done,
            ProtoconfPayloadCodec.TryWrite(
                encoded,
                ReceiveLimit,
                "Default"u8,
                includeStreamPolicies: true,
                out var bytesWritten));

        Assert.AreEqual(13, bytesWritten);
        Assert.IsTrue(encoded[..bytesWritten].SequenceEqual(
            new byte[] { 2, 0, 0, 0, 4, 7, (byte)'D', (byte)'e', (byte)'f', (byte)'a', (byte)'u', (byte)'l', (byte)'t' }));
        Assert.AreEqual(
            OperationStatus.Done,
            ProtoconfPayloadCodec.TryParse(encoded[..bytesWritten], out var parsed, out var bytesConsumed));
        Assert.AreEqual(bytesWritten, bytesConsumed);
        Assert.AreEqual<ulong>(2, parsed.FieldCount);
        Assert.AreEqual(ReceiveLimit, parsed.MaximumReceivePayloadLength);
        Assert.IsTrue(parsed.StreamPolicies.SequenceEqual("Default"u8));
        Assert.IsTrue(parsed.AdditionalFields.IsEmpty);
    }

    [TestMethod]
    public void ReaderAcceptsOneFieldAndExposesFutureFieldsWithoutCopying()
    {
        Span<byte> oneField = stackalloc byte[5];
        oneField[0] = 1;
        BinaryPrimitives.WriteUInt32LittleEndian(oneField[1..], ReceiveLimit);
        Assert.AreEqual(
            OperationStatus.Done,
            ProtoconfPayloadCodec.TryParse(oneField, out var minimal, out var minimalLength));
        Assert.AreEqual(oneField.Length, minimalLength);
        Assert.AreEqual<ulong>(1, minimal.FieldCount);
        Assert.IsTrue(minimal.StreamPolicies.IsEmpty);

        byte[] future = [3, 0, 0, 0, 4, 7, (byte)'D', (byte)'e', (byte)'f', (byte)'a', (byte)'u', (byte)'l', (byte)'t', 0xaa, 0xbb];
        Assert.AreEqual(
            OperationStatus.Done,
            ProtoconfPayloadCodec.TryParse(future, out var extended, out var extendedLength));
        Assert.AreEqual(future.Length, extendedLength);
        Assert.AreEqual<ulong>(3, extended.FieldCount);
        Assert.IsTrue(extended.StreamPolicies.SequenceEqual("Default"u8));
        Assert.IsTrue(extended.AdditionalFields.SequenceEqual(new byte[] { 0xaa, 0xbb }));
    }

    [TestMethod]
    public void WriterSupportsCallerSelectedOneFieldOrBoundedPolicy()
    {
        Span<byte> oneField = stackalloc byte[5];
        Assert.AreEqual(
            OperationStatus.Done,
            ProtoconfPayloadCodec.TryWrite(
                oneField,
                ReceiveLimit,
                streamPolicies: default,
                includeStreamPolicies: false,
                out var oneFieldLength));
        Assert.AreEqual(oneField.Length, oneFieldLength);
        Assert.AreEqual((byte)1, oneField[0]);

        Span<byte> custom = stackalloc byte[64];
        Assert.AreEqual(
            OperationStatus.Done,
            ProtoconfPayloadCodec.TryWrite(
                custom,
                ReceiveLimit,
                "Default,BlockPriority"u8,
                includeStreamPolicies: true,
                out var customLength));
        Assert.AreEqual(
            OperationStatus.Done,
            ProtoconfPayloadCodec.TryParse(custom[..customLength], out var parsed, out _));
        Assert.IsTrue(parsed.StreamPolicies.SequenceEqual("Default,BlockPriority"u8));

        Assert.AreEqual(
            OperationStatus.InvalidData,
            ProtoconfPayloadCodec.TryWrite(
                custom,
                ReceiveLimit,
                "Default"u8,
                includeStreamPolicies: false,
                out _));
    }

    [TestMethod]
    public void ReaderRejectsZeroNonCanonicalOversizedAndKnownTrailingFields()
    {
        Assert.AreEqual(
            OperationStatus.InvalidData,
            ProtoconfPayloadCodec.TryParse([0, 0, 0, 0, 0], out _, out _));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            ProtoconfPayloadCodec.TryParse([0xfd, 1, 0, 0, 0, 0, 0], out _, out _));

        byte[] oversizedPolicy = [2, 0, 0, 0, 0, 0xfd, 0x8b, 0x02];
        Assert.AreEqual(
            OperationStatus.InvalidData,
            ProtoconfPayloadCodec.TryParse(oversizedPolicy, out _, out _));

        byte[] trailingOneField = [1, 0, 0, 0, 0, 0];
        Assert.AreEqual(
            OperationStatus.InvalidData,
            ProtoconfPayloadCodec.TryParse(trailingOneField, out _, out _));

        byte[] trailingTwoFields = [2, 0, 0, 0, 0, 0, 0xaa];
        Assert.AreEqual(
            OperationStatus.InvalidData,
            ProtoconfPayloadCodec.TryParse(trailingTwoFields, out _, out _));

        var oversizedPayload = new byte[ProtoconfPayloadCodec.MaximumPayloadLength + 1];
        oversizedPayload[0] = 3;
        Assert.AreEqual(
            OperationStatus.InvalidData,
            ProtoconfPayloadCodec.TryParse(oversizedPayload, out _, out _));
    }

    [TestMethod]
    public void ReaderAcceptsCompatibilityPolicyBoundaryAndRejectsNextByte()
    {
        var maximum = CreatePolicyPayload(ProtoconfPayloadCodec.MaximumStreamPoliciesLength);
        Assert.AreEqual(
            OperationStatus.Done,
            ProtoconfPayloadCodec.TryParse(maximum, out var parsed, out _));
        Assert.AreEqual(ProtoconfPayloadCodec.MaximumStreamPoliciesLength, parsed.StreamPolicies.Length);

        var overMaximum = CreatePolicyPayload(ProtoconfPayloadCodec.MaximumStreamPoliciesLength + 1);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            ProtoconfPayloadCodec.TryParse(overMaximum, out _, out _));

        Span<byte> destination = stackalloc byte[1 + sizeof(uint) + 3 + ProtoconfPayloadCodec.MaximumStreamPoliciesLength];
        Assert.AreEqual(
            OperationStatus.Done,
            ProtoconfPayloadCodec.TryWrite(
                destination,
                ReceiveLimit,
                new byte[ProtoconfPayloadCodec.MaximumStreamPoliciesLength],
                includeStreamPolicies: true,
                out _));
        Assert.AreEqual(
            OperationStatus.InvalidData,
            ProtoconfPayloadCodec.TryWrite(
                destination,
                ReceiveLimit,
                new byte[ProtoconfPayloadCodec.MaximumStreamPoliciesLength + 1],
                includeStreamPolicies: true,
                out _));
    }

    [TestMethod]
    public void ReaderAndWriterReportEveryIncompleteLength()
    {
        Span<byte> encoded = stackalloc byte[32];
        Assert.AreEqual(
            OperationStatus.Done,
            ProtoconfPayloadCodec.TryWrite(
                encoded,
                ReceiveLimit,
                "Default"u8,
                includeStreamPolicies: true,
                out var encodedLength));

        for (var length = 0; length < encodedLength; length++)
        {
            Assert.AreEqual(
                OperationStatus.NeedMoreData,
                ProtoconfPayloadCodec.TryParse(encoded[..length], out _, out var bytesConsumed),
                $"length {length}");
            Assert.AreEqual(0, bytesConsumed);

            var destination = new byte[length];
            Array.Fill(destination, (byte)0xa5);
            Assert.AreEqual(
                OperationStatus.DestinationTooSmall,
                ProtoconfPayloadCodec.TryWrite(
                    destination,
                    ReceiveLimit,
                    "Default"u8,
                    includeStreamPolicies: true,
                    out var bytesWritten));
            Assert.AreEqual(0, bytesWritten);
            Assert.IsTrue(destination.AsSpan().IndexOfAnyExcept((byte)0xa5) < 0);
        }
    }

    private static byte[] CreatePolicyPayload(int policyLength)
    {
        var payload = new byte[1 + sizeof(uint) + 3 + policyLength];
        payload[0] = 2;
        payload[1 + sizeof(uint)] = 0xfd;
        BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(1 + sizeof(uint) + 1), (ushort)policyLength);
        return payload;
    }
}
