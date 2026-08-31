using System.Net;
using Staffetta.Core.Protocol.Cryptography;

namespace Staffetta.Bsv.LiveProbe;

internal sealed record ProbeOptions(IPEndPoint Peer, Hash256 Locator, string LocatorHex, string OutputDirectory)
{
    public static ProbeOptions Parse(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Length != 6)
        {
            throw new ArgumentException(
                "Usage: Staffetta.Bsv.LiveProbe --peer <IPv4:port> --locator <block-hash> --output <new-directory>.");
        }

        string? peerValue = null;
        string? locatorValue = null;
        string? outputValue = null;
        for (var index = 0; index < args.Length; index += 2)
        {
            var value = args[index + 1];
            switch (args[index])
            {
                case "--peer" when peerValue is null:
                    peerValue = value;
                    break;
                case "--locator" when locatorValue is null:
                    locatorValue = value;
                    break;
                case "--output" when outputValue is null:
                    outputValue = value;
                    break;
                default:
                    throw new ArgumentException($"Unknown or duplicate option '{args[index]}'.");
            }
        }

        if (!TryParsePeer(peerValue, out var peer))
        {
            throw new ArgumentException("--peer must be a literal IPv4 address and a port from 1 through 65535.");
        }

        if (!TryParseDisplayHash(locatorValue, out var locator))
        {
            throw new ArgumentException("--locator must be exactly 64 hexadecimal characters in display order.");
        }

        if (string.IsNullOrWhiteSpace(outputValue))
        {
            throw new ArgumentException("--output must name a new directory.");
        }

        return new ProbeOptions(peer, locator, locatorValue!.ToLowerInvariant(), Path.GetFullPath(outputValue));
    }

    private static bool TryParsePeer(string? value, out IPEndPoint peer)
    {
        peer = default!;
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        var separator = value.LastIndexOf(':');
        if (separator <= 0 ||
            !IPAddress.TryParse(value.AsSpan(0, separator), out var address) ||
            address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            !int.TryParse(value.AsSpan(separator + 1), out var port) ||
            port is < 1 or > IPEndPoint.MaxPort)
        {
            return false;
        }

        peer = new IPEndPoint(address, port);
        return true;
    }

    private static bool TryParseDisplayHash(string? value, out Hash256 hash)
    {
        hash = default;
        if (value?.Length != Hash256.Length * 2)
        {
            return false;
        }

        byte[] displayBytes;
        try
        {
            displayBytes = Convert.FromHexString(value);
        }
        catch (FormatException)
        {
            return false;
        }

        Span<byte> wireBytes = displayBytes;
        wireBytes.Reverse();
        return Hash256.TryCreate(wireBytes, out hash) == System.Buffers.OperationStatus.Done;
    }
}
