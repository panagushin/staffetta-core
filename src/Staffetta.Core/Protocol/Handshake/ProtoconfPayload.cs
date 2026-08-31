namespace Staffetta.Core.Protocol.Handshake;

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

    public ulong FieldCount { get; }

    public uint MaximumReceivePayloadLength { get; }

    public ReadOnlySpan<byte> StreamPolicies { get; }

    public ReadOnlySpan<byte> AdditionalFields { get; }
}
