using System.Buffers;
using Staffetta.Core.Protocol.Encoding;

namespace Staffetta.Core.Protocol.Handshake;

internal struct IncrementalProtoconfPayloadParser
{
    private IncrementalCompactSizeReader _compactSize;
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
}
