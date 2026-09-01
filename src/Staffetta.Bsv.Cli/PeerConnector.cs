using System.Net;
using System.Net.Sockets;

namespace Staffetta.Bsv.Cli;

internal interface IPeerConnection : IAsyncDisposable
{
    Stream Stream { get; }

    IPAddress RemoteAddress { get; }

    int RemotePort { get; }

    string RemoteDisplay { get; }

    void Abort();
}

internal interface IPeerConnector
{
    ValueTask<IPeerConnection> ConnectAsync(
        PeerEndpoint endpoint,
        CancellationToken cancellationToken);
}

internal sealed class TcpPeerConnector : IPeerConnector
{
    public async ValueTask<IPeerConnection> ConnectAsync(
        PeerEndpoint endpoint,
        CancellationToken cancellationToken)
    {
        var client = new TcpClient { NoDelay = true };
        try
        {
            await client.ConnectAsync(endpoint.Host, endpoint.Port, cancellationToken).ConfigureAwait(false);
            var remote = (IPEndPoint?)client.Client.RemoteEndPoint ??
                throw new SocketException((int)SocketError.NotConnected);
            return new TcpPeerConnection(client, remote);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private sealed class TcpPeerConnection : IPeerConnection
    {
        private readonly TcpClient _client;
        private readonly NetworkStream _stream;
        private int _disposed;

        internal TcpPeerConnection(TcpClient client, IPEndPoint remote)
        {
            _client = client;
            _stream = client.GetStream();
            RemoteAddress = remote.Address;
            RemotePort = remote.Port;
            RemoteDisplay = remote.ToString();
        }

        public Stream Stream => _stream;

        public IPAddress RemoteAddress { get; }

        public int RemotePort { get; }

        public string RemoteDisplay { get; }

        public void Abort() => _client.Dispose();

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _client.Dispose();
            }

            return ValueTask.CompletedTask;
        }
    }
}
