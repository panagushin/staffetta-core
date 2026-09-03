using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Relay;

/// <summary>Identifies a broadcast send intent or committed/observed fact.</summary>
public enum BsvTransactionBroadcastOutputKind
{
    /// <summary>Intent to advertise the target; no write is yet committed.</summary>
    SendInventory,
    /// <summary>The target inventory frame write was committed.</summary>
    Announced,
    /// <summary>A matching peer request was accepted after inventory commitment.</summary>
    RequestedByPeer,
    /// <summary>Intent to send the target; no transaction write is yet committed.</summary>
    SendTransaction,
    /// <summary>The target transaction frame write was committed, without claiming peer acceptance.</summary>
    SentToPeer,
    /// <summary>The peer advertised the target; this does not prove onward relay.</summary>
    ObservedFromPeer,
    /// <summary>A validated target-correlated reject was accepted after transaction write commitment.</summary>
    Rejected,
}

/// <summary>A copied broadcast output carrying an event kind and transaction identity, never transaction bytes.</summary>
/// <param name="Kind">The event kind.</param>
/// <param name="TransactionId">The target transaction associated with this output.</param>
public readonly record struct BsvTransactionBroadcastOutput(
    BsvTransactionBroadcastOutputKind Kind,
    Hash256 TransactionId);
