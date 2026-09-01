namespace Staffetta.Bsv.Cli;

internal enum CliExitCode
{
    Success = 0,
    Usage = 2,
    TransactionInput = 3,
    ConnectionFailure = 10,
    PeerSessionFailure = 11,
    Timeout = 12,
    Canceled = 130,
    InternalError = 70,
}
