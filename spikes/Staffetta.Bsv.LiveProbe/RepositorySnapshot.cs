using System.Diagnostics;

namespace Staffetta.Bsv.LiveProbe;

internal sealed record RepositorySnapshot(string Commit, string State)
{
    private static readonly TimeSpan GitTimeout = TimeSpan.FromSeconds(2);

    internal static async Task<RepositorySnapshot> ReadAsync(CancellationToken cancellationToken)
    {
        var repositoryRoot = FindRepositoryRoot(AppContext.BaseDirectory);
        if (repositoryRoot is null)
        {
            return new RepositorySnapshot("unknown", "unknown");
        }

        var commit = await RunGitLineAsync(
            repositoryRoot,
            ["rev-parse", "HEAD"],
            acceptFirstLineWithoutExit: false,
            cancellationToken).ConfigureAwait(false);
        var status = await RunGitLineAsync(
            repositoryRoot,
            ["status", "--porcelain=v1", "--untracked-files=normal"],
            acceptFirstLineWithoutExit: true,
            cancellationToken).ConfigureAwait(false);
        return new RepositorySnapshot(
            string.IsNullOrWhiteSpace(commit) ? "unknown" : commit.Trim(),
            status is null ? "clean" : status.Length == 0 ? "unknown" : "dirty");
    }

    private static string? FindRepositoryRoot(string start)
    {
        var directory = new DirectoryInfo(start);
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, ".git")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        return null;
    }

    private static async Task<string?> RunGitLineAsync(
        string workingDirectory,
        string[] arguments,
        bool acceptFirstLineWithoutExit,
        CancellationToken cancellationToken)
    {
        using var timeoutCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCancellation.CancelAfter(GitTimeout);
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "git",
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            },
        };
        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        var started = false;
        try
        {
            if (!process.Start())
            {
                return string.Empty;
            }

            started = true;
            var line = await process.StandardOutput.ReadLineAsync(timeoutCancellation.Token)
                .ConfigureAwait(false);
            if (acceptFirstLineWithoutExit && line is not null)
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }

                return line;
            }

            await process.WaitForExitAsync(timeoutCancellation.Token).ConfigureAwait(false);
            return process.ExitCode == 0 ? line : string.Empty;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }

            return string.Empty;
        }
        finally
        {
            if (started && !process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
    }
}
