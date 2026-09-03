using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Messages;

/// <summary>An inventory type and object hash, preserving unknown type values without interpretation.</summary>
public readonly struct InventoryVector : IEquatable<InventoryVector>
{
    /// <summary>Creates an inventory entry without validating its object type or hash.</summary>
    /// <param name="type">The raw unsigned inventory type.</param>
    /// <param name="hash">The advertised object identifier in wire order.</param>
    public InventoryVector(uint type, Hash256 hash)
    {
        Type = type;
        Hash = hash;
    }

    /// <summary>Gets the raw inventory type, including unrecognized values.</summary>
    public uint Type { get; }

    /// <summary>Gets the advertised object identifier in wire order.</summary>
    public Hash256 Hash { get; }

    /// <inheritdoc/>
    public bool Equals(InventoryVector other) => Type == other.Type && Hash == other.Hash;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is InventoryVector other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Type, Hash);

    /// <summary>Tests equality of both the inventory type and object hash.</summary>
    public static bool operator ==(InventoryVector left, InventoryVector right) => left.Equals(right);

    /// <summary>Tests whether the inventory type or object hash differs.</summary>
    public static bool operator !=(InventoryVector left, InventoryVector right) => !left.Equals(right);
}
