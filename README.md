# Staffetta Core

Staffetta Core is the public Apache-2.0 protocol foundation of Staffetta. It
contains reusable Bitcoin-family wire, transaction, header, and chain-profile
primitives designed for deterministic, transport-independent testing.

Production peer management, persistence, operator APIs, entitlements, and
token-product semantics belong to the private Staffetta Platform and are not
part of this repository.

The project targets .NET 10. Run `./verify` to restore, build, and test it.

The API is under active construction and has no compatibility commitment
before its first release.

## Reference BSV CLI

The reference CLI is single-peer, ephemeral, and persistence-free. Standard
output is deterministic NDJSON; diagnostics go to standard error.

```sh
dotnet run --project src/Staffetta.Bsv.Cli -- \
  handshake --peer node.example:8333

dotnet run --project src/Staffetta.Bsv.Cli -- \
  prepare-broadcast --tx-file ./transaction.bin

dotnet run --project src/Staffetta.Bsv.Cli -- \
  broadcast --peer node.example:8333 --tx-file ./transaction.bin

dotnet run --project src/Staffetta.Bsv.Cli -- \
  fetch --peer node.example:8333 --txid <display-order-transaction-id>
```

`prepare-broadcast` is strictly local. It incrementally validates and identifies
one binary legacy transaction, but never connects, announces, or broadcasts it.
The `handshake` command cannot access transaction bytes and emits only protocol
handshake traffic. `broadcast` performs the same local validation before it
connects, then uses the single peer's `inv`/`getdata`/`tx` flow. Exit code zero
requires a transport-committed `SentToPeer` fact; relay-back is reported
separately. The command does not sign, persist, or retry transactions.
`fetch` subscribes to peer relay inventory for one transaction id, commits a
matching `getdata`, and succeeds only after the full transaction has been
streamed, structurally and monetarily validated, and matched to that id. It
cannot announce or source transaction bytes.
