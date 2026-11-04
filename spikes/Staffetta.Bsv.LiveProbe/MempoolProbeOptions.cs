using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Staffetta.Bsv.LiveProbe;

internal sealed record MempoolProbeOptions(IPEndPoint Peer, string OutputDirectory, int Seconds, bool Relay, bool RequestMempool = true)
{
    internal static MempoolProbeOptions Parse(string[] args)
    {
        if (args.Length is not (8 or 10))
        {
            throw new ArgumentException("mempool --peer <IPv4:port> --output <new-directory> --seconds <10..60> --relay <true|false> [--request <true|false>]");
        }

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index += 2)
        {
            if (args[index] is not ("--peer" or "--output" or "--seconds" or "--relay" or "--request") ||
                !values.TryAdd(args[index], args[index + 1]))
            {
                throw new ArgumentException("Unknown or duplicate mempool probe option.");
            }
        }

        if (!values.TryGetValue("--peer", out var peerText) ||
            !values.TryGetValue("--output", out var output) ||
            !values.TryGetValue("--seconds", out var duration) ||
            !values.TryGetValue("--relay", out var relayText) ||
            !IPEndPoint.TryParse(peerText, out var peer) ||
            peer.AddressFamily != AddressFamily.InterNetwork || peer.Port == 0 ||
            !int.TryParse(duration, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) ||
            seconds is < 10 or > 60 || !bool.TryParse(relayText, out var relay) ||
            string.IsNullOrWhiteSpace(output))
        {
            throw new ArgumentException("Invalid mempool probe endpoint, duration, relay flag or output directory.");
        }

        var request = true;
        if (values.TryGetValue("--request", out var requestText) && !bool.TryParse(requestText, out request))
        {
            throw new ArgumentException("Invalid request flag.");
        }

        return new(peer, Path.GetFullPath(output), seconds, relay, request);
    }
}
