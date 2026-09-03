namespace Staffetta.Core.Protocol.Handshake;

/// <summary>A version payload view with explicit optional-field presence and borrowed binary fields.</summary>
/// <remarks>UserAgent and AssociationId alias caller-owned storage, which must remain valid and unchanged while this view is used. Scalar fields are copied; values are not independently authenticated peer facts.</remarks>
public readonly ref struct VersionPayload
{
    /// <summary>Creates a full outgoing version payload view without copying or validating its binary fields.</summary>
    /// <param name="protocolVersion">The advertised protocol version.</param>
    /// <param name="services">Raw advertised service bits.</param>
    /// <param name="timestampUnixSeconds">The caller-supplied Unix timestamp; no clock is read.</param>
    /// <param name="receivingAddress">The advertised receiving address.</param>
    /// <param name="sourceAddress">The advertised source address.</param>
    /// <param name="nonce">The caller-generated connection nonce.</param>
    /// <param name="userAgent">Borrowed user-agent bytes, without a length prefix.</param>
    /// <param name="startHeight">The advertised starting block height.</param>
    /// <param name="relay">The advertised transaction relay preference.</param>
    /// <param name="associationId">Borrowed optional association identifier bytes.</param>
    /// <param name="includeAssociationId">Whether to include even an empty association field; nonempty bytes always mark it present.</param>
    /// <remarks>All optional fields through Relay are marked present. The writer enforces binary field length limits.</remarks>
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

    /// <summary>Gets the advertised protocol version.</summary>
    public int ProtocolVersion { get; }

    /// <summary>Gets the raw advertised service bits.</summary>
    public ulong Services { get; }

    /// <summary>Gets the advertised Unix timestamp without interpreting its accuracy.</summary>
    public long TimestampUnixSeconds { get; }

    /// <summary>Gets the advertised receiving address.</summary>
    public NetworkAddress ReceivingAddress { get; }

    /// <summary>Gets the source address, or default when HasSourceAddress is false.</summary>
    public NetworkAddress SourceAddress { get; }

    /// <summary>Gets whether the source-address and nonce pair was present.</summary>
    public bool HasSourceAddress { get; }

    /// <summary>Gets the connection nonce, or zero when HasSourceAddress is false.</summary>
    public ulong Nonce { get; }

    /// <summary>Gets borrowed user-agent bytes; empty bytes do not by themselves indicate absence.</summary>
    public ReadOnlySpan<byte> UserAgent { get; }

    /// <summary>Gets whether a user-agent field was present, including an empty field.</summary>
    public bool HasUserAgent { get; }

    /// <summary>Gets the advertised starting block height, or zero when absent.</summary>
    public int StartHeight { get; }

    /// <summary>Gets whether a starting-height field was present.</summary>
    public bool HasStartHeight { get; }

    /// <summary>Gets the relay preference; parsing defaults an absent field to true without marking it present.</summary>
    public bool Relay { get; }

    /// <summary>Gets whether an explicit relay preference was present.</summary>
    public bool HasRelay { get; }

    /// <summary>Gets borrowed association identifier bytes, which may be empty even when present.</summary>
    public ReadOnlySpan<byte> AssociationId { get; }

    /// <summary>Gets whether an association identifier field was present, including a present-empty field.</summary>
    public bool HasAssociationId { get; }
}
