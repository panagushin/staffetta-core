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
```

`prepare-broadcast` is strictly local. It incrementally validates and identifies
one binary legacy transaction, but never connects, announces, or broadcasts it.
The `handshake` command cannot access transaction bytes and emits only protocol
handshake traffic.
