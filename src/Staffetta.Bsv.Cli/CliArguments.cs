using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Bsv.Cli;

internal enum ReferenceCliCommand
{
    Handshake,
    PrepareBroadcast,
    Broadcast,
    Fetch,
}

internal readonly record struct PeerEndpoint(string Host, int Port)
{
    internal string Display => Host.Contains(':', StringComparison.Ordinal)
        ? $"[{Host}]:{Port.ToString(CultureInfo.InvariantCulture)}"
        : $"{Host}:{Port.ToString(CultureInfo.InvariantCulture)}";
}

internal sealed record CliArguments(
    ReferenceCliCommand Command,
    PeerEndpoint? Peer,
    string? TransactionFile,
    TimeSpan ConnectTimeout,
    TimeSpan HandshakeTimeout,
    TimeSpan BroadcastTimeout = default,
    Hash256? TransactionId = null,
    TimeSpan FetchTimeout = default)
{
    internal const int DefaultConnectTimeoutMilliseconds = 5_000;
    internal const int DefaultHandshakeTimeoutMilliseconds = 30_000;
    internal const int DefaultBroadcastTimeoutMilliseconds = 30_000;
    internal const int DefaultFetchTimeoutMilliseconds = 30_000;

    internal static bool TryParse(
        IReadOnlyList<string> arguments,
        out CliArguments? parsed,
        out bool showHelp,
        out string? error)
    {
        parsed = null;
        showHelp = false;
        error = null;
        if (arguments.Count == 1 && arguments[0] is "--help" or "-h")
        {
            showHelp = true;
            return true;
        }

        if (arguments.Count == 0 || !TryParseCommand(arguments[0], out var command))
        {
            error = "Expected command 'handshake', 'prepare-broadcast', 'broadcast', or 'fetch'.";
            return false;
        }

        PeerEndpoint? peer = null;
        string? transactionFile = null;
        Hash256? transactionId = null;
        var connectTimeout = DefaultConnectTimeoutMilliseconds;
        var handshakeTimeout = DefaultHandshakeTimeoutMilliseconds;
        var broadcastTimeout = DefaultBroadcastTimeoutMilliseconds;
        var fetchTimeout = DefaultFetchTimeoutMilliseconds;
        var hasConnectTimeout = false;
        var hasHandshakeTimeout = false;
        var hasBroadcastTimeout = false;
        var hasFetchTimeout = false;
        var hasPeer = false;
        var hasTransactionFile = false;
        var hasTransactionId = false;
        for (var index = 1; index < arguments.Count; index++)
        {
            var option = arguments[index];
            if (option is "--help" or "-h")
            {
                showHelp = true;
                return true;
            }

            if (++index >= arguments.Count)
            {
                error = $"Option '{option}' requires a value.";
                return false;
            }

            var value = arguments[index];
            switch (option)
            {
                case "--peer":
                    if (hasPeer)
                    {
                        error = "Option '--peer' may be specified only once.";
                        return false;
                    }

                    if (!TryParsePeer(value, out var parsedPeer))
                    {
                        error = "Peer must be host:port or [IPv6]:port with a port from 1 to 65535.";
                        return false;
                    }

                    peer = parsedPeer;
                    hasPeer = true;
                    break;
                case "--tx-file":
                    if (hasTransactionFile)
                    {
                        error = "Option '--tx-file' may be specified only once.";
                        return false;
                    }

                    if (string.IsNullOrWhiteSpace(value))
                    {
                        error = "Transaction file path cannot be empty.";
                        return false;
                    }

                    transactionFile = value;
                    hasTransactionFile = true;
                    break;
                case "--txid":
                    if (hasTransactionId)
                    {
                        error = "Option '--txid' may be specified only once.";
                        return false;
                    }

                    if (!TryParseDisplayTransactionId(value, out var parsedTransactionId))
                    {
                        error = "Transaction id must be exactly 64 hexadecimal display-order characters.";
                        return false;
                    }

                    transactionId = parsedTransactionId;
                    hasTransactionId = true;
                    break;
                case "--connect-timeout-ms":
                    if (hasConnectTimeout)
                    {
                        error = "Option '--connect-timeout-ms' may be specified only once.";
                        return false;
                    }

                    if (!TryParsePositiveMilliseconds(value, out connectTimeout))
                    {
                        error = "Connect timeout must be a positive integer number of milliseconds.";
                        return false;
                    }

                    hasConnectTimeout = true;

                    break;
                case "--handshake-timeout-ms":
                    if (hasHandshakeTimeout)
                    {
                        error = "Option '--handshake-timeout-ms' may be specified only once.";
                        return false;
                    }

                    if (!TryParsePositiveMilliseconds(value, out handshakeTimeout))
                    {
                        error = "Handshake timeout must be a positive integer number of milliseconds.";
                        return false;
                    }

                    hasHandshakeTimeout = true;

                    break;
                case "--broadcast-timeout-ms":
                    if (hasBroadcastTimeout)
                    {
                        error = "Option '--broadcast-timeout-ms' may be specified only once.";
                        return false;
                    }

                    if (!TryParsePositiveMilliseconds(value, out broadcastTimeout))
                    {
                        error = "Broadcast timeout must be a positive integer number of milliseconds.";
                        return false;
                    }

                    hasBroadcastTimeout = true;
                    break;
                case "--fetch-timeout-ms":
                    if (hasFetchTimeout)
                    {
                        error = "Option '--fetch-timeout-ms' may be specified only once.";
                        return false;
                    }

                    if (!TryParsePositiveMilliseconds(value, out fetchTimeout))
                    {
                        error = "Fetch timeout must be a positive integer number of milliseconds.";
                        return false;
                    }

                    hasFetchTimeout = true;
                    break;
                default:
                    error = $"Unknown option '{option}'.";
                    return false;
            }
        }

        if (command is ReferenceCliCommand.Handshake or ReferenceCliCommand.Broadcast or ReferenceCliCommand.Fetch &&
            peer is null)
        {
            error = "Option '--peer' is required.";
            return false;
        }

        if (command is ReferenceCliCommand.PrepareBroadcast or ReferenceCliCommand.Broadcast && transactionFile is null)
        {
            error = "Option '--tx-file' is required for prepare-broadcast and broadcast.";
            return false;
        }

        if (command == ReferenceCliCommand.Handshake && transactionFile is not null)
        {
            error = "Option '--tx-file' is valid only for prepare-broadcast or broadcast.";
            return false;
        }

        if (command == ReferenceCliCommand.Fetch && transactionId is null)
        {
            error = "Option '--txid' is required for fetch.";
            return false;
        }

        if (command != ReferenceCliCommand.Fetch && transactionId is not null)
        {
            error = "Option '--txid' is valid only for fetch.";
            return false;
        }

        if (command == ReferenceCliCommand.Fetch && transactionFile is not null)
        {
            error = "fetch observes a peer and does not accept '--tx-file'.";
            return false;
        }

        if (command == ReferenceCliCommand.PrepareBroadcast && peer is not null)
        {
            error = "prepare-broadcast is local and does not accept '--peer'.";
            return false;
        }

        if (command == ReferenceCliCommand.PrepareBroadcast &&
            (hasConnectTimeout || hasHandshakeTimeout || hasBroadcastTimeout))
        {
            error = "prepare-broadcast is local and does not accept network timeouts.";
            return false;
        }

        if (command == ReferenceCliCommand.Handshake && hasBroadcastTimeout)
        {
            error = "Option '--broadcast-timeout-ms' is valid only for broadcast.";
            return false;
        }

        if (command != ReferenceCliCommand.Broadcast && hasBroadcastTimeout)
        {
            error = "Option '--broadcast-timeout-ms' is valid only for broadcast.";
            return false;
        }

        if (command != ReferenceCliCommand.Fetch && hasFetchTimeout)
        {
            error = "Option '--fetch-timeout-ms' is valid only for fetch.";
            return false;
        }

        parsed = new CliArguments(
            command,
            peer,
            transactionFile,
            TimeSpan.FromMilliseconds(connectTimeout),
            TimeSpan.FromMilliseconds(handshakeTimeout),
            TimeSpan.FromMilliseconds(broadcastTimeout),
            transactionId,
            TimeSpan.FromMilliseconds(fetchTimeout));
        return true;
    }

    private static bool TryParseCommand(string value, out ReferenceCliCommand command)
    {
        command = value switch
        {
            "handshake" => ReferenceCliCommand.Handshake,
            "prepare-broadcast" => ReferenceCliCommand.PrepareBroadcast,
            "broadcast" => ReferenceCliCommand.Broadcast,
            "fetch" => ReferenceCliCommand.Fetch,
            _ => default,
        };
        return value is "handshake" or "prepare-broadcast" or "broadcast" or "fetch";
    }

    private static bool TryParseDisplayTransactionId(string value, out Hash256 transactionId)
    {
        transactionId = default;
        if (value.Length != Hash256.Length * 2)
        {
            return false;
        }

        Span<byte> bytes = stackalloc byte[Hash256.Length];
        if (Convert.FromHexString(value, bytes, out var charsConsumed, out var bytesWritten) !=
                System.Buffers.OperationStatus.Done ||
            charsConsumed != value.Length ||
            bytesWritten != bytes.Length)
        {
            return false;
        }

        bytes.Reverse();
        return Hash256.TryCreate(bytes, out transactionId) == System.Buffers.OperationStatus.Done;
    }

    private static bool TryParsePeer(string value, out PeerEndpoint endpoint)
    {
        endpoint = default;
        string host;
        string portText;
        if (value.StartsWith('['))
        {
            var closingBracket = value.IndexOf(']');
            if (closingBracket <= 1 || closingBracket + 2 >= value.Length || value[closingBracket + 1] != ':')
            {
                return false;
            }

            host = value[1..closingBracket];
            portText = value[(closingBracket + 2)..];
            if (!IPAddress.TryParse(host, out var address) ||
                address.AddressFamily != AddressFamily.InterNetworkV6)
            {
                return false;
            }
        }
        else
        {
            var separator = value.LastIndexOf(':');
            if (separator <= 0 || separator == value.Length - 1 || value[..separator].Contains(':', StringComparison.Ordinal))
            {
                return false;
            }

            host = value[..separator];
            portText = value[(separator + 1)..];
            if (!IsIpv4OrDnsName(host))
            {
                return false;
            }
        }

        if (string.IsNullOrWhiteSpace(host) ||
            !int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out var port) ||
            port is < 1 or > ushort.MaxValue)
        {
            return false;
        }

        endpoint = new PeerEndpoint(host, port);
        return true;
    }

    private static bool IsIpv4OrDnsName(string host)
    {
        if (host.Any(char.IsWhiteSpace) ||
            host.Contains('/', StringComparison.Ordinal) ||
            host.Contains('\\', StringComparison.Ordinal) ||
            host.Contains('[', StringComparison.Ordinal) ||
            host.Contains(']', StringComparison.Ordinal))
        {
            return false;
        }

        if (IPAddress.TryParse(host, out var address))
        {
            return address.AddressFamily == AddressFamily.InterNetwork;
        }

        return Uri.CheckHostName(host) == UriHostNameType.Dns;
    }

    private static bool TryParsePositiveMilliseconds(string value, out int milliseconds) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out milliseconds) &&
        milliseconds > 0;
}
