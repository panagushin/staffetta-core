namespace Staffetta.Core.Protocol.Handshake;

/// <summary>A parsed protoconf view whose policy and future-field bytes borrow the input buffer.</summary>
public readonly ref struct ProtoconfPayload
{
    internal ProtoconfPayload(
        ulong fieldCount,
        uint maximumReceivePayloadLength,
        ReadOnlySpan<byte> streamPolicies,
        ReadOnlySpan<byte> additionalFields)
    {
        FieldCount = fieldCount;
        MaximumReceivePayloadLength = maximumReceivePayloadLength;
        StreamPolicies = streamPolicies;
        AdditionalFields = additionalFields;
    }

    /// <summary>Gets the declared field count; unknown future fields are not individually decoded.</summary>
    public ulong FieldCount { get; }

    /// <summary>Gets the advertised receive limit in bytes; handshake policy decides whether it is acceptable.</summary>
    public uint MaximumReceivePayloadLength { get; }

    /// <summary>Gets borrowed policy bytes without their length prefix, or empty when absent.</summary>
    public ReadOnlySpan<byte> StreamPolicies { get; }

    /// <summary>Gets borrowed opaque trailing bytes for declared future fields; their structure is not validated.</summary>
    public ReadOnlySpan<byte> AdditionalFields { get; }
}
