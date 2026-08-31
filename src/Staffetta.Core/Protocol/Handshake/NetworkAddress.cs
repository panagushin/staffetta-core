using System.Buffers.Binary;

namespace Staffetta.Core.Protocol.Handshake;

public readonly record struct NetworkAddress
{
    private const ulong Ipv4MappedPrefixMask = 0xffff_ffff_0000_0000UL;
    private const ulong Ipv4MappedPrefix = 0x0000_ffff_0000_0000UL;

    private readonly ulong _addressHigh;
    private readonly ulong _addressLow;

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

    public ulong Services { get; }

    public ushort Port { get; }

    public bool IsIpv4Mapped =>
        _addressHigh == 0 &&
        (_addressLow & Ipv4MappedPrefixMask) == Ipv4MappedPrefix;

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

    public bool TryWriteIpv4(Span<byte> destination)
    {
        if (!IsIpv4Mapped || destination.Length < sizeof(uint))
        {
            return false;
        }

        BinaryPrimitives.WriteUInt32BigEndian(destination, (uint)_addressLow);
        return true;
    }

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
