using System.Buffers;

namespace Staffetta.Core.Protocol.Handshake;

internal struct IncrementalProtoconfPayloadParser
{
    private CompactSizeAccumulator _compactSize;
    private ParseState _state;
    private ulong _fieldCount;
    private uint _maximumReceivePayloadLength;
    private int _receiveLimitBytesRead;
    private ulong _policyBytesRemaining;

    public void Reset()
    {
        this = default;
        _state = ParseState.FieldCount;
    }

    public void Consume(ReadOnlySpan<byte> source)
    {
        if (_state == ParseState.Invalid)
        {
            return;
        }

        var offset = 0;
        while (offset < source.Length)
        {
            switch (_state)
            {
                case ParseState.FieldCount:
                    offset += _compactSize.Consume(source[offset..]);
                    if (!_compactSize.IsComplete)
                    {
                        return;
                    }

                    if (!_compactSize.IsCanonical || _compactSize.Value == 0)
                    {
                        _state = ParseState.Invalid;
                        return;
                    }

                    _fieldCount = _compactSize.Value;
                    _compactSize = default;
                    _state = ParseState.ReceiveLimit;
                    break;

                case ParseState.ReceiveLimit:
                    while (offset < source.Length && _receiveLimitBytesRead < sizeof(uint))
                    {
                        _maximumReceivePayloadLength |= (uint)source[offset] << (_receiveLimitBytesRead * 8);
                        _receiveLimitBytesRead++;
                        offset++;
                    }

                    if (_receiveLimitBytesRead == sizeof(uint))
                    {
                        _state = _fieldCount == 1
                            ? ParseState.ExactEnd
                            : ParseState.PolicyLength;
                    }

                    break;

                case ParseState.PolicyLength:
                    offset += _compactSize.Consume(source[offset..]);
                    if (!_compactSize.IsComplete)
                    {
                        return;
                    }

                    if (!_compactSize.IsCanonical ||
                        _compactSize.Value > ProtoconfPayloadCodec.MaximumStreamPoliciesLength)
                    {
                        _state = ParseState.Invalid;
                        return;
                    }

                    _policyBytesRemaining = _compactSize.Value;
                    _compactSize = default;
                    if (_policyBytesRemaining == 0)
                    {
                        _state = _fieldCount == 2
                            ? ParseState.ExactEnd
                            : ParseState.OpaqueTail;
                    }
                    else
                    {
                        _state = ParseState.Policy;
                    }

                    break;

                case ParseState.Policy:
                    var skippedLength = (int)Math.Min(
                        (ulong)(source.Length - offset),
                        _policyBytesRemaining);
                    _policyBytesRemaining -= (ulong)skippedLength;
                    offset += skippedLength;
                    if (_policyBytesRemaining == 0)
                    {
                        _state = _fieldCount == 2
                            ? ParseState.ExactEnd
                            : ParseState.OpaqueTail;
                    }

                    break;

                case ParseState.OpaqueTail:
                    return;

                case ParseState.ExactEnd:
                    _state = ParseState.Invalid;
                    return;

                default:
                    _state = ParseState.Invalid;
                    return;
            }
        }
    }

    public OperationStatus Complete(out uint maximumReceivePayloadLength)
    {
        maximumReceivePayloadLength = 0;
        switch (_state)
        {
            case ParseState.ExactEnd:
            case ParseState.OpaqueTail:
                maximumReceivePayloadLength = _maximumReceivePayloadLength;
                return OperationStatus.Done;
            case ParseState.Invalid:
                return OperationStatus.InvalidData;
            default:
                return OperationStatus.NeedMoreData;
        }
    }

    private enum ParseState
    {
        FieldCount,
        ReceiveLimit,
        PolicyLength,
        Policy,
        ExactEnd,
        OpaqueTail,
        Invalid,
    }

    private struct CompactSizeAccumulator
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
}
