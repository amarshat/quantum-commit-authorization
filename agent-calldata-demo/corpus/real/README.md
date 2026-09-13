# Real drainer / phishing corpus

Drop labeled real transactions here as `*.json` files. `demo/corpus.py`'s
`real_cases()` loads every `*.json` in this directory; each file is a JSON list of
records. Unknown keys are ignored, so you can keep provenance fields.

**What is here.** `ptxphish_sample.json` is the reconstructed corpus the papers
measure on: 140 victim-signed rows (101 malicious, 39 benign controls),
reconstructed from the PTXPHISH release (NDSS 2025, arXiv 2409.02386) by
recovering each victim's own signed grant from `Approval` / `ApprovalForAll`
logs rather than the attacker's later sweep. It ships in this repo, so
`./run.sh` reproduces the reported numbers without any additional data
collection.

(This file previously said the repo ships "the loader and schema, not a bundled
dataset". That stopped being true when the reconstructed sample landed, and the
stale sentence read as a missing artifact to anyone checking reproducibility.)

**Adding more.** `demo/corpus.py`'s `real_cases()` loads every `*.json` in this
directory, so further labeled sources (on-chain-labeled drainer transactions, a
ScamSniffer or BlockSec feed) can be dropped in alongside. Record the source and
label of every case.

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
