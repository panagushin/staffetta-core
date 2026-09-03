using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Core.Protocol.Relay;

/// <summary>Identifies a fetch request intent or validated/committed observation.</summary>
public enum BsvTransactionFetchOutputKind
{
    /// <summary>Intent to request the target; no request write is yet committed.</summary>
    SendGetData,
    /// <summary>The target getdata frame write was committed.</summary>
    Requested,
    /// <summary>A validated transaction's computed identifier differs from the target.</summary>
    UnexpectedTransaction,
    /// <summary>A validated transaction matched the target, even if no request write had committed.</summary>
    Received,
    /// <summary>A matching notfound was accepted after request write commitment.</summary>
    NotFound,
}

/// <summary>A copied fetch output carrying an event kind and transaction identity, never transaction bytes.</summary>
/// <param name="Kind">The event kind.</param>
/// <param name="TransactionId">The target identifier, except UnexpectedTransaction carries the actual received identifier.</param>
public readonly record struct BsvTransactionFetchOutput(
    BsvTransactionFetchOutputKind Kind,
    Hash256 TransactionId);
