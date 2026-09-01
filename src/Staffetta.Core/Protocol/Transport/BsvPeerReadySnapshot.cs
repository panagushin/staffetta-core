namespace Staffetta.Core.Protocol.Transport;

internal readonly record struct BsvPeerReadySnapshot(
    int ProtocolVersion,
    uint EffectiveMaximumReceivePayloadLength,
    bool HasProtoconf);
