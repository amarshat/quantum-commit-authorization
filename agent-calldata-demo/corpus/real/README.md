# Real drainer / phishing corpus

Drop labeled real transactions here as `*.json` files. `demo/corpus.py`'s
`real_cases()` loads every `*.json` in this directory; each file is a JSON list of
records. Unknown keys are ignored, so you can keep provenance fields.

This repo ships the loader and schema, **not** a bundled dataset. The measurement
against hosted defenses (Tenderly, GoPlus) is only meaningful once real records
are here. Populate from a labeled source, for example the PTXPHISH release
(NDSS 2025, arXiv 2409.02386), on-chain-labeled drainer transactions, or a
ScamSniffer / BlockSec feed. Record the source and label of every case.

## Record schema

Required for a hosted-defense (Tenderly) simulation:

| field | meaning |
|-------|---------|
| `id` | stable unique id |
| `source` | `"real"` (defaulted if omitted) |
| `label` | ground-truth category, e.g. `approval-drain`, `permit-phish`, `7702-delegation`, `benign` |
| `malicious` | `true` for a drain, `false` for a benign control |
| `kind` | `"onchain"` or `"offchain_sig"` |
| `action_type` | `approve` \| `transfer` \| `call` \| `permit` \| `order` \| `delegation` \| `permit2_approve` |
| `chain_id` | e.g. `1` for mainnet |
| `frm` | signer / sender (the owner whose funds are at risk) |
| `to` | tx target (on-chain) or verifying contract (off-chain sig) |
| `input` | calldata (on-chain); `""` for an off-chain signature |
| `value` | wei value (string) |

Ground-truth context (used to score open-rule defenses; fill what you can):

`counterparty`, `recipient`, `amount` (decimal string or `"UNLIMITED"`),
`counterparty_is_contract`, `recipient_is_contract`, `counterparty_known`,
`recipient_known`.

Provenance (optional): `tx_hash`, `block`, `note`.

Include benign controls (`malicious: false`) so per-defense false-positive rates
can be measured, not just catch rates. See `example.json.template` for the shape.
