using Staffetta.Core.Protocol.Cryptography;
using Staffetta.Core.Protocol.Handshake;
using Staffetta.Core.Protocol.Relay;

namespace Staffetta.Core.Protocol.Transport;

internal interface IBsvTransactionPayloadSourceProvider
{
    ValueTask<IBsvTransactionPayloadSource?> OpenAsync(
        Hash256 transactionId,
        CancellationToken cancellationToken);
}

internal interface IBsvTransactionPayloadSource : IAsyncDisposable
{
    Hash256 TransactionId { get; }

    ulong Length { get; }

    ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken);
}

internal interface IBsvPeerSessionFactSink
{
    ValueTask OnHandshakeFactAsync(
        BsvHandshakeOutput output,
        CancellationToken cancellationToken);

    ValueTask OnBroadcastFactAsync(
        BsvTransactionBroadcastOutput output,
        CancellationToken cancellationToken);

    ValueTask OnFetchFactAsync(
        BsvTransactionFetchOutput output,
        CancellationToken cancellationToken);
}
