namespace Staffetta.Core.Protocol.Transport;

internal sealed class BsvPeerStreamTransportOptions
{
    internal const int DefaultBufferLength = 64 * 1024;
    internal const int MaximumBufferLength = 1024 * 1024;

    internal BsvPeerStreamTransportOptions(
        int readBufferLength = DefaultBufferLength,
        int transactionBufferLength = DefaultBufferLength,
        int maximumWriteLength = DefaultBufferLength,
        bool leaveOpen = false)
    {
        ValidateLength(readBufferLength, nameof(readBufferLength));
        ValidateLength(transactionBufferLength, nameof(transactionBufferLength));
        ValidateLength(maximumWriteLength, nameof(maximumWriteLength));

        ReadBufferLength = readBufferLength;
        TransactionBufferLength = transactionBufferLength;
        MaximumWriteLength = maximumWriteLength;
        LeaveOpen = leaveOpen;
    }

    internal int ReadBufferLength { get; }

    internal int TransactionBufferLength { get; }

    internal int MaximumWriteLength { get; }

    internal bool LeaveOpen { get; }

    private static void ValidateLength(int value, string parameterName)
    {
        if (value is <= 0 or > MaximumBufferLength)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                value,
                $"Buffer lengths must be between 1 and {MaximumBufferLength} bytes.");
        }
    }
}
