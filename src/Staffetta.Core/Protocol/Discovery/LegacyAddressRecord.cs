using Staffetta.Core.Protocol.Handshake;

namespace Staffetta.Core.Protocol.Discovery;

public readonly record struct LegacyAddressRecord(
    uint TimestampUnixSeconds,
    NetworkAddress Address);
