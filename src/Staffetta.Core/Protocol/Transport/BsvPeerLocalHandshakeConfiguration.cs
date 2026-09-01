using Staffetta.Core.Protocol.Handshake;

namespace Staffetta.Core.Protocol.Transport;

internal sealed class BsvPeerLocalHandshakeConfiguration
{
    private readonly byte[] _userAgent;
    private readonly byte[] _associationId;
    private readonly byte[] _streamPolicies;

    internal BsvPeerLocalHandshakeConfiguration(
        int protocolVersion,
        ulong services,
        long timestampUnixSeconds,
        NetworkAddress receivingAddress,
        NetworkAddress sourceAddress,
        ulong nonce,
        ReadOnlySpan<byte> userAgent,
        int startHeight,
        bool relay,
        uint maximumReceivePayloadLength,
        ReadOnlySpan<byte> streamPolicies,
        bool includeStreamPolicies,
        ReadOnlySpan<byte> associationId = default,
        bool includeAssociationId = false)
    {
        if (userAgent.Length > VersionPayloadCodec.MaximumUserAgentLength)
        {
            throw new ArgumentOutOfRangeException(nameof(userAgent));
        }

        if (associationId.Length > VersionPayloadCodec.MaximumAssociationIdLength)
        {
            throw new ArgumentOutOfRangeException(nameof(associationId));
        }

        if (streamPolicies.Length > ProtoconfPayloadCodec.MaximumStreamPoliciesLength ||
            (!includeStreamPolicies && !streamPolicies.IsEmpty))
        {
            throw new ArgumentOutOfRangeException(nameof(streamPolicies));
        }

        ProtocolVersion = protocolVersion;
        Services = services;
        TimestampUnixSeconds = timestampUnixSeconds;
        ReceivingAddress = receivingAddress;
        SourceAddress = sourceAddress;
        Nonce = nonce;
        StartHeight = startHeight;
        Relay = relay;
        MaximumReceivePayloadLength = maximumReceivePayloadLength;
        IncludeStreamPolicies = includeStreamPolicies;
        IncludeAssociationId = includeAssociationId || !associationId.IsEmpty;
        _userAgent = userAgent.ToArray();
        _associationId = associationId.ToArray();
        _streamPolicies = streamPolicies.ToArray();
    }

    internal ulong Nonce { get; }

    internal uint MaximumReceivePayloadLength { get; }

    internal ReadOnlySpan<byte> StreamPolicies => _streamPolicies;

    internal bool IncludeStreamPolicies { get; }

    private int ProtocolVersion { get; }

    private ulong Services { get; }

    private long TimestampUnixSeconds { get; }

    private NetworkAddress ReceivingAddress { get; }

    private NetworkAddress SourceAddress { get; }

    private int StartHeight { get; }

    private bool Relay { get; }

    private bool IncludeAssociationId { get; }

    internal VersionPayload CreateVersionPayload() =>
        new(
            ProtocolVersion,
            Services,
            TimestampUnixSeconds,
            ReceivingAddress,
            SourceAddress,
            Nonce,
            _userAgent,
            StartHeight,
            Relay,
            _associationId,
            IncludeAssociationId);
}
