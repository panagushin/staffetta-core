using System.Buffers;
using Staffetta.Core.Protocol.Blocks;
using Staffetta.Core.Protocol.Messages;

namespace Staffetta.Core.Protocol.Sessions;

internal sealed class BsvPeerObservationBuffers
{
    private readonly InventoryVector[] _inventory;
    private readonly BlockHeader[] _headers;
    private readonly byte[] _headerPayload;
    private int _stagedInventoryCount;
    private int _headerPayloadLength;

    internal BsvPeerObservationBuffers(int maximumInventoryCount, int maximumHeaderCount)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumInventoryCount, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumInventoryCount, 50_000);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumHeaderCount, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumHeaderCount, HeadersPayloadCodec.MaximumHeaderCount);
        _inventory = new InventoryVector[maximumInventoryCount];
        _headers = new BlockHeader[maximumHeaderCount];
        _headerPayload = new byte[3 + maximumHeaderCount * 81];
    }

    internal ulong MaximumHeaderPayloadLength => (ulong)_headerPayload.Length;
    internal int PendingInventoryCount { get; private set; }
    internal int PendingHeaderCount { get; private set; }
    internal bool HasPendingInventory { get; private set; }
    internal bool HasPendingHeaders { get; private set; }
    internal bool HasPending => HasPendingInventory || HasPendingHeaders;

    internal bool StageInventory(in InventoryVector vector)
    {
        if (_stagedInventoryCount == _inventory.Length)
        {
            return false;
        }

        _inventory[_stagedInventoryCount++] = vector;
        return true;
    }

    internal void CommitInventory()
    {
        PendingInventoryCount = _stagedInventoryCount;
        HasPendingInventory = true;
    }

    internal OperationStatus StageHeaders(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > _headerPayload.Length - _headerPayloadLength)
        {
            return OperationStatus.InvalidData;
        }

        bytes.CopyTo(_headerPayload.AsSpan(_headerPayloadLength));
        _headerPayloadLength += bytes.Length;
        return OperationStatus.Done;
    }

    internal OperationStatus CommitHeaders()
    {
        if (HeadersPayloadCodec.TryParse(_headerPayload.AsSpan(0, _headerPayloadLength), _headers,
                out var count) != OperationStatus.Done)
        {
            return OperationStatus.InvalidData;
        }

        PendingHeaderCount = count;
        HasPendingHeaders = true;
        return OperationStatus.Done;
    }

    internal OperationStatus DrainInventory(Span<InventoryVector> destination, out int count)
    {
        count = 0;
        if (destination.Length < PendingInventoryCount)
        {
            return OperationStatus.DestinationTooSmall;
        }

        count = PendingInventoryCount;
        _inventory.AsSpan(0, count).CopyTo(destination);
        _inventory.AsSpan(0, count).Clear();
        PendingInventoryCount = 0;
        HasPendingInventory = false;
        return OperationStatus.Done;
    }

    internal OperationStatus DrainHeaders(Span<BlockHeader> destination, out int count)
    {
        count = 0;
        if (destination.Length < PendingHeaderCount)
        {
            return OperationStatus.DestinationTooSmall;
        }

        count = PendingHeaderCount;
        _headers.AsSpan(0, count).CopyTo(destination);
        _headers.AsSpan(0, count).Clear();
        PendingHeaderCount = 0;
        HasPendingHeaders = false;
        return OperationStatus.Done;
    }

    internal void ResetStaging()
    {
        if (!HasPendingInventory)
        {
            _inventory.AsSpan(0, _stagedInventoryCount).Clear();
        }

        _stagedInventoryCount = 0;
        _headerPayload.AsSpan(0, _headerPayloadLength).Clear();
        _headerPayloadLength = 0;
    }

    internal void Discard()
    {
        HasPendingInventory = false;
        HasPendingHeaders = false;
        PendingInventoryCount = 0;
        PendingHeaderCount = 0;
        _inventory.AsSpan().Clear();
        _headers.AsSpan().Clear();
        ResetStaging();
    }
}
