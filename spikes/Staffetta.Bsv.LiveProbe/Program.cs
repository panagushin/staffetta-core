namespace Staffetta.Bsv.LiveProbe;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args is ["mempool", .. var mempoolArgs])
            {
                return await MempoolProbe.RunAsync(MempoolProbeOptions.Parse(mempoolArgs)).ConfigureAwait(false);
            }

            var options = ProbeOptions.Parse(args);
            await LiveProbe.RunAsync(options, CancellationToken.None).ConfigureAwait(false);
            return 0;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or TimeoutException)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
    }
}
