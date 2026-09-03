# Staffetta Core

Staffetta Core is an Apache-2.0 .NET library and reference CLI for Bitcoin-family
protocol work, with a BSV implementation. It provides wire codecs, streaming
legacy transaction parsing, BSV handshake and relay state machines, and Merkle
path verification. Protocol decisions are tested without sockets; the CLI
connects these components to a single BSV peer.

Production peer management, persistence, operator APIs, entitlements, and
token-product semantics belong to the private Staffetta Platform and are not
part of this repository.

This is pre-release software, not a full node or a production wallet. BTC
witness transactions and additional network profiles are not implemented.
Internal transport and header-chain orchestration are not a supported library
API. No API compatibility or production-readiness commitment is made before
the first release.

## Build and verify

Install a .NET 10 SDK accepted by `global.json` (10.0.203 or a later patch in
that SDK feature band), then run from the repository root:

```sh
./verify
```

Verification restores and builds in Release, runs offline tests with a hang
deadline, runs allocation evidence separately, then packs and consumes a local
smoke package. XML documentation is generated and missing public API docs fail
the build. No live peer connections or transaction broadcasts are part of
verification.

The package smoke restores only from a temporary local feed and checks the
archive contents, documentation, license, README, repository commit, and a
consumer using public APIs. The CLI, tests, and live probe are not packable.
To produce a local development package after verification:

```sh
dotnet pack src/Staffetta.Core --configuration Release --no-build --no-restore
```

This does not publish anything. The default version is `0.0.0-dev`, not a
release designation.

## Library example

With a reference to `Staffetta.Core`, canonical CompactSize values can be read
from caller-owned memory:

```csharp
using System.Buffers;
using Staffetta.Core.Protocol.Encoding;

byte[] bytes = [0xfd, 0xfd, 0x00];
OperationStatus status = CompactSize.Read(bytes, out ulong value, out int consumed);
// Done: value is 253 and consumed is 3. Non-minimal encodings are rejected.
```

The generated XML documentation describes each codec's consumption and failure
contract. Incremental transaction and message consumers operate on bounded
chunks rather than materializing arbitrary scripts or payloads. Chunk lifetime
and provisional callback rules matter: consumers must not publish derived
effects before the enclosing validation succeeds.

Structural transaction parsing does not validate scripts or spendability.
`MerkleInclusionVerifier` checks a txid's path to a supplied root; callers must
separately establish the root's relationship to their selected admitted chain.
Without a full transaction list, a path does not authenticate the entire
block's tree shape or the absence of duplicates elsewhere.

## Reference BSV CLI

The reference CLI is single-peer, ephemeral, and persistence-free. Standard
output is versioned NDJSON with ordered event sequences; diagnostics go to
standard error. Network observations naturally vary between runs.

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
`fetch` waits for peer relay inventory for one transaction id, commits a
matching `getdata`, and succeeds only after the full transaction has been
streamed, structurally and monetarily validated, and matched to that id. It
cannot announce or source transaction bytes.

`broadcast` sends an already signed transaction on BSV mainnet and can spend
real funds. Use only transaction bytes and peers you intend to use; it is not
a dry run. `SentToPeer` means a transport write was committed, not that a miner
accepted or included the transaction. Run `--help` for timeout controls.

## Contributing and security

Contributions are Apache-2.0 with the [Developer Certificate of Origin](https://developercertificate.org/).
Sign off commits with `git commit -s` and run `./verify`; there is no CLA.
Report suspected vulnerabilities privately as described in [SECURITY.md](https://github.com/panagushin/staffetta-core/blob/main/SECURITY.md).
See [LICENSE](LICENSE) for the license text.
