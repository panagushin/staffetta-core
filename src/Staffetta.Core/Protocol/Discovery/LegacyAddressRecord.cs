using Staffetta.Core.Protocol.Handshake;

namespace Staffetta.Core.Protocol.Discovery;

/// <summary>A timestamped legacy addr record advertised by a peer, without reachability verification.</summary>
/// <param name="TimestampUnixSeconds">The peer-supplied last-seen timestamp in Unix seconds.</param>
/// <param name="Address">The advertised services, address bytes, and port.</param>
public readonly record struct LegacyAddressRecord(
    uint TimestampUnixSeconds,
    NetworkAddress Address);
