namespace Staffetta.Core.Protocol.Handshake;

public readonly ref struct VersionPayload
{
    public VersionPayload(
        int protocolVersion,
        ulong services,
        long timestampUnixSeconds,
        NetworkAddress receivingAddress,
        NetworkAddress sourceAddress,
        ulong nonce,
        ReadOnlySpan<byte> userAgent,
        int startHeight,
        bool relay,
        ReadOnlySpan<byte> associationId = default,
        bool includeAssociationId = false)
        : this(
            protocolVersion,
            services,
            timestampUnixSeconds,
            receivingAddress,
            sourceAddress,
            hasSourceAddress: true,
            nonce,
            userAgent,
            hasUserAgent: true,
            startHeight,
            hasStartHeight: true,
            relay,
            hasRelay: true,
            associationId,
            hasAssociationId: includeAssociationId || !associationId.IsEmpty)
    {
    }

    internal VersionPayload(
        int protocolVersion,
        ulong services,
        long timestampUnixSeconds,
        NetworkAddress receivingAddress,
        NetworkAddress sourceAddress,
        bool hasSourceAddress,
        ulong nonce,
        ReadOnlySpan<byte> userAgent,
        bool hasUserAgent,
        int startHeight,
        bool hasStartHeight,
        bool relay,
        bool hasRelay,
        ReadOnlySpan<byte> associationId,
        bool hasAssociationId)
    {
        ProtocolVersion = protocolVersion;
        Services = services;
        TimestampUnixSeconds = timestampUnixSeconds;
        ReceivingAddress = receivingAddress;
        SourceAddress = sourceAddress;
        HasSourceAddress = hasSourceAddress;
        Nonce = nonce;
        UserAgent = userAgent;
        HasUserAgent = hasUserAgent;
        StartHeight = startHeight;
        HasStartHeight = hasStartHeight;
        Relay = relay;
        HasRelay = hasRelay;
        AssociationId = associationId;
        HasAssociationId = hasAssociationId;
    }

    public int ProtocolVersion { get; }

    public ulong Services { get; }

    public long TimestampUnixSeconds { get; }

    public NetworkAddress ReceivingAddress { get; }

    public NetworkAddress SourceAddress { get; }

    public bool HasSourceAddress { get; }

    public ulong Nonce { get; }

    public ReadOnlySpan<byte> UserAgent { get; }

    public bool HasUserAgent { get; }

    public int StartHeight { get; }

    public bool HasStartHeight { get; }

    public bool Relay { get; }

    public bool HasRelay { get; }

    public ReadOnlySpan<byte> AssociationId { get; }

    public bool HasAssociationId { get; }
}
