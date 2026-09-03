# Security

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/panagushin/staffetta-core/security/advisories/new)
for suspected security defects. Do not disclose exploit details in public issues
or pull requests before coordinated disclosure.

Include the affected commit or package version, runtime and operating system,
impact, and a minimal offline reproducer when possible. Do not send private
keys, signing material, access tokens, customer data, or funded transactions.
Use synthetic inputs rather than attacking live peers to demonstrate a bug.

## Support status

Core is pre-release software with no stable supported release line yet. Reports
against the current `main` branch are welcome. This project does not promise a
response-time SLA, a bug bounty, or production suitability.

## Trust boundaries

Peer traffic, declared lengths, transaction bytes, and supplied proofs are
untrusted. Please report memory growth controlled by untrusted lengths,
unbounded waits, parsing or hash discrepancies, reentrancy violations, and any
case where provisional data is presented as a validated or committed fact.

Core is not a full node, wallet, key vault, or complete consensus validator.
Structural transaction acceptance is not script validity or spendability.
A Merkle path reaching a supplied root does not by itself establish an admitted
selected-chain block. A peer write or announcement is not mining confirmation.
Applications remain responsible for resource budgets, durable state, access
control, and the trust provenance of imported header checkpoints.
