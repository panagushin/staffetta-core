using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Relay;

public enum BsvTransactionBroadcastOutputKind
{
    SendInventory,
    Announced,
    RequestedByPeer,
    SendTransaction,
    SentToPeer,
    ObservedFromPeer,
    Rejected,
}

public readonly record struct BsvTransactionBroadcastOutput(
    BsvTransactionBroadcastOutputKind Kind,
    Hash256 TransactionId);
