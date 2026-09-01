namespace Staffetta.Core.Protocol.Handshake;

internal sealed class BsvHandshakeEgressIntentQueue
{
    private readonly BsvHandshakeOutput[] _items =
        new BsvHandshakeOutput[BsvHandshakeStateMachine.MaximumOutputCount];

    internal int Count { get; private set; }

    internal bool TryEnqueueFromOutputs(ReadOnlySpan<BsvHandshakeOutput> outputs)
    {
        if (Count != 0)
        {
            return false;
        }

        foreach (ref readonly var output in outputs)
        {
            if (IsSendIntent(output.Kind))
            {
                _items[Count++] = output;
            }
        }

        return true;
    }

    internal bool TryPeek(out BsvHandshakeOutput output)
    {
        if (Count == 0)
        {
            output = default;
            return false;
        }

        output = _items[0];
        return true;
    }

    internal bool TryConsume(in BsvHandshakeOutput expected)
    {
        if (Count == 0 || _items[0] != expected)
        {
            return false;
        }

        Count--;
        _items.AsSpan(1, Count).CopyTo(_items);
        _items[Count] = default;
        return true;
    }

    internal void Clear()
    {
        _items.AsSpan().Clear();
        Count = 0;
    }

    private static bool IsSendIntent(BsvHandshakeOutputKind kind) =>
        kind is BsvHandshakeOutputKind.SendVersion or
            BsvHandshakeOutputKind.SendVerack or
            BsvHandshakeOutputKind.SendProtoconf or
            BsvHandshakeOutputKind.SendPong or
            BsvHandshakeOutputKind.SendPing;
}
