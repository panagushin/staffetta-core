using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Messages;

public readonly struct InventoryVector : IEquatable<InventoryVector>
{
    public InventoryVector(uint type, Hash256 hash)
    {
        Type = type;
        Hash = hash;
    }

    public uint Type { get; }

    public Hash256 Hash { get; }

    public bool Equals(InventoryVector other) => Type == other.Type && Hash == other.Hash;

    public override bool Equals(object? obj) => obj is InventoryVector other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(Type, Hash);

    public static bool operator ==(InventoryVector left, InventoryVector right) => left.Equals(right);

    public static bool operator !=(InventoryVector left, InventoryVector right) => !left.Equals(right);
}
