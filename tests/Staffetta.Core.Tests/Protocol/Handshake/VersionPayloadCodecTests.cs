using System.Buffers;
using System.Buffers.Binary;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Staffetta.Core.Protocol.Handshake;

namespace Staffetta.Core.Tests.Protocol.Handshake;

[TestClass]
public sealed class VersionPayloadCodecTests
{
    private static ReadOnlySpan<byte> UserAgent => "/staffetta/"u8;

    [TestMethod]
    public void CurrentVersionRoundTripsRawCallerSuppliedFields()
    {
        var encoded = WriteVersion(
            services: 0x8000_0000_0000_0021,
            timestamp: -1_700_000_000,
            nonce: 0xdead_beef_cafe_babe,
            associationId: [0, 1, 2, 3],
            includeAssociationId: true);

        Assert.AreEqual(
            OperationStatus.Done,
            VersionPayloadCodec.TryParse(encoded, out var parsed, out var bytesConsumed));

        Assert.AreEqual(encoded.Length, bytesConsumed);
        Assert.AreEqual(VersionPayloadCodec.CurrentProtocolVersion, parsed.ProtocolVersion);
        Assert.AreEqual<ulong>(0x8000_0000_0000_0021, parsed.Services);
        Assert.AreEqual(-1_700_000_000, parsed.TimestampUnixSeconds);
        Assert.AreEqual<ulong>(0xdead_beef_cafe_babe, parsed.Nonce);
        Assert.IsTrue(parsed.UserAgent.SequenceEqual(UserAgent));
        Assert.AreEqual(948_321, parsed.StartHeight);
        Assert.IsFalse(parsed.Relay);
        Assert.IsTrue(parsed.AssociationId.SequenceEqual(new byte[] { 0, 1, 2, 3 }));
        Assert.IsTrue(parsed.HasSourceAddress);
        Assert.IsTrue(parsed.HasUserAgent);
        Assert.IsTrue(parsed.HasStartHeight);
        Assert.IsTrue(parsed.HasRelay);
        Assert.IsTrue(parsed.HasAssociationId);
    }

    [TestMethod]
    public void OptionalTailAcceptsOnlyCompleteFieldBoundaries()
    {
        var encoded = WriteVersion(
            services: 1,
            timestamp: 2,
            nonce: 3,
            associationId: default,
            includeAssociationId: false);
        var userAgentBoundary = VersionPayloadCodec.RequiredPrefixLength + 34 + 1 + UserAgent.Length;
        var startHeightBoundary = userAgentBoundary + sizeof(int);
        var relayBoundary = startHeightBoundary + sizeof(byte);
        int[] validLengths =
        [
            VersionPayloadCodec.RequiredPrefixLength,
            VersionPayloadCodec.RequiredPrefixLength + 34,
            userAgentBoundary,
            startHeightBoundary,
            relayBoundary,
        ];

        for (var length = 0; length <= encoded.Length; length++)
        {
            var status = VersionPayloadCodec.TryParse(encoded.AsSpan(0, length), out _, out var bytesConsumed);
            if (validLengths.Contains(length))
            {
                Assert.AreEqual(OperationStatus.Done, status, $"length {length}");
                Assert.AreEqual(length, bytesConsumed, $"length {length}");
            }
            else
            {
                Assert.AreEqual(OperationStatus.NeedMoreData, status, $"length {length}");
                Assert.AreEqual(0, bytesConsumed, $"length {length}");
            }
        }
    }

    [TestMethod]
    public void RequiredPrefixUsesAbsentFieldDefaultsWithoutSynthesizingPresence()
    {
        var full = WriteVersion(1, 2, 3, default, includeAssociationId: false);
        var prefix = full.AsSpan(0, VersionPayloadCodec.RequiredPrefixLength);

        Assert.AreEqual(
            OperationStatus.Done,
            VersionPayloadCodec.TryParse(prefix, out var parsed, out var bytesConsumed));

        Assert.AreEqual(prefix.Length, bytesConsumed);
        Assert.IsFalse(parsed.HasSourceAddress);
        Assert.IsFalse(parsed.HasUserAgent);
        Assert.IsFalse(parsed.HasStartHeight);
        Assert.IsFalse(parsed.HasRelay);
        Assert.IsFalse(parsed.HasAssociationId);
        Assert.IsTrue(parsed.Relay);
    }

    [TestMethod]
    public void AssociationDistinguishesAbsentPresentEmptyAndPresentValue()
    {
        var absent = WriteVersion(1, 2, 3, default, includeAssociationId: false);
        var presentEmpty = WriteVersion(1, 2, 3, default, includeAssociationId: true);
        var presentValue = WriteVersion(1, 2, 3, [0x42], includeAssociationId: true);

        Assert.AreEqual(OperationStatus.Done, VersionPayloadCodec.TryParse(absent, out var absentParsed, out _));
        Assert.IsFalse(absentParsed.HasAssociationId);
        Assert.AreEqual(OperationStatus.Done, VersionPayloadCodec.TryParse(presentEmpty, out var emptyParsed, out _));
        Assert.IsTrue(emptyParsed.HasAssociationId);
        Assert.IsTrue(emptyParsed.AssociationId.IsEmpty);
        Assert.AreEqual(OperationStatus.Done, VersionPayloadCodec.TryParse(presentValue, out var valueParsed, out _));
        Assert.IsTrue(valueParsed.HasAssociationId);
        Assert.IsTrue(valueParsed.AssociationId.SequenceEqual(new byte[] { 0x42 }));
    }

    [TestMethod]
    public void ParserRejectsNonCanonicalOrOversizedBoundedFieldsAndInvalidBool()
    {
        var encoded = WriteVersion(1, 2, 3, default, includeAssociationId: false);
        var userAgentOffset = VersionPayloadCodec.RequiredPrefixLength + 34;

        var nonCanonicalUserAgent = new byte[userAgentOffset + 3];
        encoded.AsSpan(0, userAgentOffset).CopyTo(nonCanonicalUserAgent);
        nonCanonicalUserAgent[userAgentOffset] = 0xfd;
        nonCanonicalUserAgent[userAgentOffset + 1] = 1;
        Assert.AreEqual(
            OperationStatus.InvalidData,
            VersionPayloadCodec.TryParse(nonCanonicalUserAgent, out _, out _));

        var oversizedUserAgent = new byte[userAgentOffset + 3];
        encoded.AsSpan(0, userAgentOffset).CopyTo(oversizedUserAgent);
        oversizedUserAgent[userAgentOffset] = 0xfd;
        BinaryPrimitives.WriteUInt16LittleEndian(oversizedUserAgent.AsSpan(userAgentOffset + 1), 257);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            VersionPayloadCodec.TryParse(oversizedUserAgent, out _, out _));

        var invalidRelay = (byte[])encoded.Clone();
        invalidRelay[^1] = 2;
        Assert.AreEqual(
            OperationStatus.InvalidData,
            VersionPayloadCodec.TryParse(invalidRelay, out _, out _));
    }

    [TestMethod]
    public void AssociationLengthAndTrailingGarbageAreRejected()
    {
        var maximum = new byte[VersionPayloadCodec.MaximumAssociationIdLength];
        Array.Fill(maximum, (byte)0x5a);
        var encoded = WriteVersion(1, 2, 3, maximum, includeAssociationId: true);
        Assert.AreEqual(OperationStatus.Done, VersionPayloadCodec.TryParse(encoded, out _, out _));

        var tooLarge = new byte[encoded.Length - maximum.Length + 3];
        encoded.AsSpan(0, encoded.Length - maximum.Length - 1).CopyTo(tooLarge);
        var offset = encoded.Length - maximum.Length - 1;
        tooLarge[offset] = 0xfd;
        BinaryPrimitives.WriteUInt16LittleEndian(tooLarge.AsSpan(offset + 1), 130);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            VersionPayloadCodec.TryParse(tooLarge, out _, out _));

        var oneByteAssociation = WriteVersion(1, 2, 3, [0x42], includeAssociationId: true);
        var trailingGarbage = new byte[oneByteAssociation.Length + 1];
        oneByteAssociation.CopyTo(trailingGarbage, 0);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            VersionPayloadCodec.TryParse(trailingGarbage, out _, out _));
    }

    [TestMethod]
    public void WriterChecksBoundsAndEveryDestinationLengthBeforeWriting()
    {
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [127, 0, 0, 1], 8_333, out var receiving));
        var source = new NetworkAddress(2, new byte[16], 0);
        var payload = new VersionPayload(
            VersionPayloadCodec.CurrentProtocolVersion,
            3,
            4,
            receiving,
            source,
            5,
            UserAgent,
            6,
            relay: true);
        Span<byte> complete = stackalloc byte[512];
        Assert.AreEqual(
            OperationStatus.Done,
            VersionPayloadCodec.TryWrite(complete, payload, out var completeLength));

        for (var length = 0; length < completeLength; length++)
        {
            var destination = new byte[length];
            Array.Fill(destination, (byte)0xa5);
            Assert.AreEqual(
                OperationStatus.DestinationTooSmall,
                VersionPayloadCodec.TryWrite(destination, payload, out var bytesWritten));
            Assert.AreEqual(0, bytesWritten);
            Assert.IsTrue(destination.AsSpan().IndexOfAnyExcept((byte)0xa5) < 0);
        }

        var oversizedUserAgent = new byte[VersionPayloadCodec.MaximumUserAgentLength + 1];
        var invalid = new VersionPayload(
            VersionPayloadCodec.CurrentProtocolVersion,
            3,
            4,
            receiving,
            source,
            5,
            oversizedUserAgent,
            6,
            relay: true);
        Assert.AreEqual(
            OperationStatus.InvalidData,
            VersionPayloadCodec.TryWrite(complete, invalid, out var invalidLength));
        Assert.AreEqual(0, invalidLength);

        var maximumUserAgent = new byte[VersionPayloadCodec.MaximumUserAgentLength];
        var maximum = new VersionPayload(
            VersionPayloadCodec.CurrentProtocolVersion,
            3,
            4,
            receiving,
            source,
            5,
            maximumUserAgent,
            6,
            relay: true);
        Assert.AreEqual(
            OperationStatus.Done,
            VersionPayloadCodec.TryWrite(complete, maximum, out _));
    }

    private static byte[] WriteVersion(
        ulong services,
        long timestamp,
        ulong nonce,
        ReadOnlySpan<byte> associationId,
        bool includeAssociationId)
    {
        Assert.IsTrue(NetworkAddress.TryCreateIpv4(1, [192, 0, 2, 1], 8_333, out var receiving));
        var source = new NetworkAddress(2, new byte[16], 0);
        var payload = new VersionPayload(
            VersionPayloadCodec.CurrentProtocolVersion,
            services,
            timestamp,
            receiving,
            source,
            nonce,
            UserAgent,
            948_321,
            relay: false,
            associationId,
            includeAssociationId);
        var destination = new byte[512];
        Assert.AreEqual(
            OperationStatus.Done,
            VersionPayloadCodec.TryWrite(destination, payload, out var bytesWritten));
        return destination[..bytesWritten];
    }
}
