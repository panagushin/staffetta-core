using System.Buffers.Binary;

namespace Staffetta.Core.Protocol.Handshake;

/// <summary>A copied 16-byte network address, raw service flags, and host-order port, without a timestamp.</summary>
public readonly record struct NetworkAddress
{
    private const ulong Ipv4MappedPrefixMask = 0xffff_ffff_0000_0000UL;
    private const ulong Ipv4MappedPrefix = 0x0000_ffff_0000_0000UL;

    private readonly ulong _addressHigh;
    private readonly ulong _addressLow;

    /// <summary>Copies a 16-byte IPv6 or IPv4-mapped address into a value.</summary>
    /// <param name="services">Raw advertised service bits.</param>
    /// <param name="address">Exactly sixteen address bytes in network order; not retained.</param>
    /// <param name="port">The port as a host-order numeric value.</param>
    /// <exception cref="ArgumentException">The address does not contain exactly sixteen bytes.</exception>
    public NetworkAddress(ulong services, ReadOnlySpan<byte> address, ushort port)
    {
        if (address.Length != 16)
        {
            throw new ArgumentException("A network address must contain exactly 16 bytes.", nameof(address));
        }

        Services = services;
        _addressHigh = BinaryPrimitives.ReadUInt64BigEndian(address);
        _addressLow = BinaryPrimitives.ReadUInt64BigEndian(address[sizeof(ulong)..]);
        Port = port;
    }

    /// <summary>Gets the raw advertised service bits.</summary>
    public ulong Services { get; }

    /// <summary>Gets the port as a host-order numeric value.</summary>
    public ushort Port { get; }

    /// <summary>Gets whether the stored bytes use the IPv4-mapped IPv6 prefix.</summary>
    public bool IsIpv4Mapped =>
        _addressHigh == 0 &&
        (_addressLow & Ipv4MappedPrefixMask) == Ipv4MappedPrefix;

    /// <summary>Copies four IPv4 octets into an IPv4-mapped address value.</summary>
    /// <param name="services">Raw advertised service bits.</param>
    /// <param name="address">Exactly four IPv4 bytes in network order; not retained.</param>
    /// <param name="port">The port as a host-order numeric value.</param>
    /// <param name="networkAddress">The copied value on success; otherwise default.</param>
    /// <returns>True for exactly four address bytes; otherwise false.</returns>
    public static bool TryCreateIpv4(
        ulong services,
        ReadOnlySpan<byte> address,
        ushort port,
        out NetworkAddress networkAddress)
    {
        networkAddress = default;
        if (address.Length != sizeof(uint))
        {
            return false;
        }

        Span<byte> mappedAddress = stackalloc byte[16];
        mappedAddress[10] = 0xff;
        mappedAddress[11] = 0xff;
        address.CopyTo(mappedAddress[12..]);
        networkAddress = new NetworkAddress(services, mappedAddress, port);
        return true;
    }

    /// <summary>Writes four IPv4 octets into caller-owned storage when this address is IPv4-mapped.</summary>
    /// <returns>True on success; false without writing if not mapped or fewer than four bytes are available.</returns>
    public bool TryWriteIpv4(Span<byte> destination)
    {
        if (!IsIpv4Mapped || destination.Length < sizeof(uint))
        {
            return false;
        }

        BinaryPrimitives.WriteUInt32BigEndian(destination, (uint)_addressLow);
        return true;
    }

    /// <summary>Writes all sixteen address bytes into caller-owned storage in network order.</summary>
    /// <returns>True on success; false without writing if fewer than sixteen bytes are available.</returns>
    public bool TryWriteAddress(Span<byte> destination)
    {
        if (destination.Length < 16)
        {
            return false;
        }

        BinaryPrimitives.WriteUInt64BigEndian(destination, _addressHigh);
        BinaryPrimitives.WriteUInt64BigEndian(destination[sizeof(ulong)..], _addressLow);
        return true;
    }
}
