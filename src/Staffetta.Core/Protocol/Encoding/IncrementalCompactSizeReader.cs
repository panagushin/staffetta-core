namespace Staffetta.Core.Protocol.Encoding;

internal struct IncrementalCompactSizeReader
{
    private byte _prefix;
    private byte _bytesRead;
    private byte _encodedLength;
    private ulong _value;

    public bool IsComplete => _encodedLength > 0 && _bytesRead == _encodedLength;

    public bool IsCanonical => IsComplete && _prefix switch
    {
        < 0xfd => true,
        0xfd => _value >= 0xfd,
        0xfe => _value > ushort.MaxValue,
        _ => _value > uint.MaxValue,
    };

    public ulong Value => _value;

    public int Consume(ReadOnlySpan<byte> source)
    {
        var offset = 0;
        if (_bytesRead == 0 && !source.IsEmpty)
        {
            _prefix = source[0];
            _bytesRead = 1;
            _encodedLength = _prefix switch
            {
                < 0xfd => 1,
                0xfd => 3,
                0xfe => 5,
                _ => 9,
            };
            _value = _prefix < 0xfd ? _prefix : 0UL;
            offset = 1;
        }

        while (offset < source.Length && _bytesRead < _encodedLength)
        {
            _value |= (ulong)source[offset] << ((_bytesRead - 1) * 8);
            _bytesRead++;
            offset++;
        }

        return offset;
    }
}
