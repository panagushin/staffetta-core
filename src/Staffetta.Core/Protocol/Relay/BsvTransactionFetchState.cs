namespace Staffetta.Core.Protocol.Relay;

/// <summary>The phase of a one-peer fetch for a single transaction.</summary>
public enum BsvTransactionFetchState
{
    /// <summary>No target transaction has been selected.</summary>
    Created,
    /// <summary>Waiting for matching inventory; a matching validated transaction can already complete the fetch.</summary>
    AwaitingInventory,
    /// <summary>A getdata intent exists but its write has not committed.</summary>
    GetDataWritePending,
    /// <summary>The getdata write committed and a response is awaited.</summary>
    Requested,
    /// <summary>A validated transaction matched the target; this is a successful terminal state.</summary>
    Received,
    /// <summary>A matching notfound was accepted after request commitment; this is terminal.</summary>
    NotFound,
    /// <summary>Disconnection or another failure ended the fetch.</summary>
    Terminal,
}

/// <summary>The failure reason for a fetch in the Terminal state.</summary>
public enum BsvTransactionFetchTerminalReason
{
    /// <summary>No failure reason has been recorded, including Received and NotFound outcomes.</summary>
    None,
    /// <summary>The caller reported peer disconnection.</summary>
    Disconnected,
    /// <summary>The caller reported invalid wire data.</summary>
    WireViolation,
    /// <summary>The caller reported a non-protocol failure.</summary>
    ExternalFailure,
}
