# Which wallet capability stops an agent's poisoned signature

An AI agent that holds a wallet decides what to do in English, but what it
signs is calldata or a typed message. A poisoned tool can hand it a benign
sentence and a malicious signature. That gap is known. This repo does not claim
a new attack. It maps something narrower and, I think, more useful: given a
poisoned-tool drain, which wallet-defense capability actually stops it, and
which drains survive a capability-complete stack.

The short answer, from the runnable harness below: rendering the counterparty,
the amount, and the ultimate recipient of a signed action closes the
stranger-target and recipient-substitution drains. Transaction and signature
simulation add nothing beyond that for the hard cases. What is left is one
on-chain time-of-check/time-of-use race that only re-simulation at inclusion
catches, plus authorizations (EIP-7702 delegation, Permit2 approval) whose
danger is categorical rather than visible in any field. And those residual
cases lean on the allowlisted target itself being adversarial.

This is a coverage map, not a measurement, and the arms below are capability
models, not the branded products. See "What this is and is not" before quoting
any of it.

**Paper:** *An Address Allowlist Gates the Counterparty, Not the Grant* —
[10.5281/zenodo.21470174](https://doi.org/10.5281/zenodo.21470174) (CC-BY-4.0).
**Explainer:** <https://amarshat.github.io/quantum-commit-authorization/agent-drains.html>
**Interactive:** <https://amarshat.github.io/quantum-commit-authorization/agent-drains-demo.html> (pick a drain, toggle defenses, generated from `out/scorecard.json` by `demo/build_pages.py`)

This lives in the [quantum-commit-authorization](../README.md) repo but is a
separate piece of work from the post-quantum protocol there. Shared repo, no
shared code or threat model; see [Also in this
repo](../README.md#also-in-this-repo-an-agent-wallet-drain-coverage-map) for the
one honest thread that links them.

## Run it

Requires [Foundry](https://getfoundry.sh) (`anvil`, `cast`, `forge`) and
`python3`. No `pip`/`npm` to run the core; the harness shells out to `cast`.

```bash
./run.sh
```

It boots a local `anvil` (on the Prague hardfork, needed for the EIP-7702 row),
deploys a mock USDC, and runs eight poisoned-tool drains against a ladder of
seven defense capabilities, printing the coverage matrix and writing
`out/scorecard.{json,md}`.

## The capability ladder

Real wallet defenses are not one thing. They are a stack of capabilities a
wallet may or may not have. The ladder, weakest first:

1. **plan-review (English only)** — reads the agent's stated plan text, never
   the bytes. This is an LLM plan-reviewer or a prompt-injection guardrail. It
   can be a real one: set `ANTHROPIC_API_KEY` (needs `pip install anthropic`)
   and/or `LAKERA_GUARD_API_KEY` and this rung calls them.
2. **address allowlist** — decode the action and veto if the counterparty is
   not on the allowlist.
3. **amount-aware clear-signing** — also veto unlimited amounts, even to an
   allowlisted counterparty.
4. **recipient rendering** — also render the *ultimate recipient* when it is a
   signed field distinct from the counterparty (an order's `taker`, a bridge's
   destination). This is what [ERC-7730](https://eips.ethereum.org/EIPS/eip-7730)
   descriptors do.
5. **transaction simulation** — fork-run the transaction and veto on an adverse
   state diff. (This rung actually forks the chain.)
6. **signature simulation** — reason about the net transfer a signature enables,
   which is what Blowfish/Blockaid-style signing checks do.
7. **tx-type policy** — categorical warnings on dangerous action *types*
   (unlimited approval, account delegation, Permit2 approval), regardless of
   target.

Each attack is scored by the *lowest* rung that would stop the drain.

## The eight drains

Chosen to separate two axes: where the malice lives (on-chain calldata vs an
off-chain signed message) and whether the value goes to a stranger or to an
allowlisted address.

| id | drain | decoded target / recipient |
|----|-------|-----------------------------|
| A | on-chain unlimited `approve` to a stranger | counterparty = attacker |
| B | `transfer` to a stranger, dressed up as paying the merchant | counterparty = attacker |
| C | off-chain EIP-2612 `permit` to a stranger | spender = attacker |
| D | off-chain **unlimited** `permit` to the allowlisted router | spender = router (allowlisted) |
| E | on-chain call to the allowlisted router, armed after the dry-run | callee = router (allowlisted) |
| F | off-chain EIP-712 order to the allowlisted exchange | counterparty = exchange; **recipient = attacker** |
| G | off-chain EIP-7702 authorization to the allowlisted helper | delegate = helper (allowlisted) |
| H | on-chain max `approve` to the allowlisted Permit2 contract | counterparty = Permit2 (allowlisted) |

## The coverage matrix

```
attack                     plan   allow  amt    recip  txsim  sigsim type   stopped-at
A-approve-max              .      STOP   .      .      STOP   .      STOP   L2 address allowlist
B-transfer-swap            .      STOP   .      .      STOP   .      .      L2 address allowlist
C-permit-attacker          .      STOP   .      .      .      STOP   STOP   L2 address allowlist
D-permit-router-unlimited  .      .      STOP   .      .      .      STOP   L3 amount-aware clear-sign
E-honeypot-toctou          .      .      .      .      .      .      .      RESIDUAL
F-order-sign               .      .      .      STOP   .      STOP   .      L4 recipient rendering
G-delegate-7702            .      .      .      .      .      .      STOP   L7 tx-type policy
H-permit2-approval         .      .      .      .      .      .      STOP   L7 tx-type policy
```

How to read it, honestly:

- **plan-review (L1) catches none of them**, because every stated intent is
  benign by construction. That is the one thing the reasoning layer cannot fix:
  the malice is not in the text. It is a single conceptual point, not eight, and
  it is why the English column is all `.`.
- **A, B, C fall at the address allowlist (L2).** On-chain or off-chain, malice
  to a *stranger* is caught the moment you decode the counterparty. The classic
  "AI drains its wallet" is the easy case.
- **D falls at amount-awareness (L3).** An unlimited permit to an allowlisted
  router is caught by flagging "unlimited," a check wallets like Rabby ship
  today. The address allowlist alone misses it; amount rendering catches it.
- **F falls at recipient rendering (L4).** The order's counterparty is the
  allowlisted exchange, but the order's `taker` is a signed field, and once a
  clear-signer renders it the attacker recipient is visible. This is why F is not
  special: a field-complete decoder sees it.
- **Simulation (L5, L6) adds nothing here, and that is the point.** Every drain
  simulation would catch was already caught by field rendering. And simulation
  specifically misses E and G (see below).
- **G and H fall only at the categorical tx-type policy (L7).** An EIP-7702
  authorization has no field to inspect except the delegate address (allowlisted)
  and no amount; a signature simulation of the authorization shows no transfer,
  because the sweep is a separate later call. Nothing short of "warn on all
  delegations" stops G. H is the on-chain max approval to Permit2, which every
  policy must allow (an amount policy that fired on it would fire on every
  legitimate DeFi setup), so it passes L2 through L6; only a categorical
  Permit2-approval warning flags it, and that warning is impractical for the
  same reason. Note also (see concessions) that H's *approval* is benign; the
  actual drain is a later Permit2 signature whose spender is the attacker, which
  the address allowlist (L2) catches exactly like C.
- **E survives the whole ladder.** The call target is the allowlisted router,
  the inner arguments are benign, and a dry-run of the call is a benign no-op.
  Between that dry-run and the real transaction the attacker arms the contract,
  so the malicious state does not exist at check time. No static clear-signer or
  simulator sees it; only re-simulation at inclusion does.

The honest takeaway: a field-complete clear-signing stack (counterparty +
amount + recipient), which is where 2026 wallets are heading, closes A through
D and F. The genuinely hard residue is two shapes: an on-chain TOCTOU that needs
dynamic re-simulation (E), and categorically-dangerous authorization types
(EIP-7702, Permit2) that no field analysis flags (G, H). Both hard shapes also
require the allowlisted target itself to be adversarial.

## Live reputation (GoPlus), the one measured dimension

The ladder above is capability models. One dimension is wired to a real deployed
service: address reputation, via the [GoPlus Security](https://gopluslabs.io)
API. Set `GO_PLUS_APP_KEY` and `GO_PLUS_APP_SECRET` in a `.env` (gitignored) and
`./run.sh` adds a live pass that queries GoPlus for the reputation of each
attack's counterparty and recipient.

The measured result:

```
attack                     counterparty           recipient
A-approve-max              clean                  (same)
...  (all eight)           clean                  clean/(same)
G-delegate-7702            clean                  (same)

GoPlus flagged 0/8 attacks.
positive control 0x098B716B8Aaf21512996dC57EB0615e2383E2f96:
  flags = blacklist_doubt, sanctioned, stealing_attack
```

Reputation scanning catches none of the eight, because every sink is a fresh
address with no history. The positive control (a real address GoPlus flags as
`stealing_attack` / `sanctioned`) confirms the query works, so the zero is a
real finding, not a broken call: reputation only fires on addresses already
known to be bad, and a poisoned tool routes to a fresh one. Reputation is
orthogonal to the clear-signing ladder and defeated by address rotation.

GoPlus is a reputation service, not a simulator, so it cannot upgrade the
simulation rungs (L5, L6); those stay models until wired to a real simulation
API (Tenderly, or Blockaid/Blowfish's gated scan APIs).

## Source availability on the authority object (Etherscan)

*Powered by [Etherscan.io](https://etherscan.io) APIs.*

Every other tier inspects the transaction. None reads the *code* of the contract
that will govern the outcome, and answering that requires a prior question: which
contract actually decides what happens here? For most drain shapes it is not the
transaction target.

Set `ETHERSCAN_API_KEY` in the `.env` and `demo/measure.py` adds a fourth column.
It resolves the authority object, then reports whether a code reader would have
anything to read. States are **availability, not detection**: `catch` means
verified source exists for the governing object, `blind` means code but no source,
`na` means no code at all. It deliberately does not judge whether the code is
malicious; hand-rolling a malice classifier would be a strawman of the agentic
analysers this is meant to characterise.

Measured over the 101 malicious victim-signed cases:

```
class      rows  the tx `to`                             authority object      state
approve      21  12 verified blue-chip tokens            the spender           na  (EOA)
                 (stETH, USDT, BoredApeYachtClub, PEPE,
                  wstETH, rETH, RPL, an Aave proxy)
transfer     20  OpenSea Seaport TransferHelper          the recipient         na  (EOA) x19
upgradeTo    20  the victim's own OpenSea                the new               catch x16
                 OwnableDelegateProxy (verified, benign)  implementation       blind x3, na x1
other call   40  the attacker's own contract             the same contract     catch x36, blind x4

totals: catch 52, blind 8, na 41
the tx target is verified but is NOT the authority object: 61 / 101
```

So in 61 of 101 rows the readable contract is legitimate, verified, famous
infrastructure, and a source reader pointed at it correctly answers "fine",
because the code *is* fine. The theft lives in the arguments: an EOA spender, an
EOA recipient, or a replacement implementation address. **Source availability on
the target is nearly total and nearly useless. Object selection is the bottleneck,
not availability.**

Two bounds. Etherscan exposes no verification date, so we cannot establish whether
a contract's source was public at the moment the victim signed; availability is
measured as of now and is therefore an upper bound, exactly as the reputation
tier's hits are. And 20 `upgradeTo` rows resolve to only 6 distinct
implementations, so those are reported as counts, not rates.

## Intent settlement: does the signed order govern what executes?

*Powered by [Etherscan.io](https://etherscan.io) APIs.*

Everything above measures a transaction the user signs directly. An intent system
inverts that: the user signs an *order* and never authors the settlement
transaction. A solver does, later, and supplies the calls that run against the
user's approved balance.

`demo/intent_gap.py` decodes CoW Protocol settlements and asks how many of the
contracts that actually execute appear anywhere in the signed order.

What this run was expected to show, including the confirmation and falsification
thresholds, was written down before it ran: see [PREDICTION.md](PREDICTION.md).
That file also says plainly what its dates do and do not establish, since it was
published here after the measurement rather than before it. One of its three
claims was mis-specified and is left in place rather than quietly fixed.

```bash
python3 -m demo.intent_gap --windows 7 --per-window 25 --spacing-days 45
```

Over 174 settlements sampled across seven days spread over nine months:

```
median |T\S|/|T|   0.845        (share of executing contracts named in no order)
mean               0.794
all absent         84/174        settlements naming none of them
none absent         0/174        settlements naming all of them
distinct contracts governing execution but named in no order: 77
```

Of those 77, ten have no published source (the most used governs 22 of the 174
settlements) and five sit behind upgradeable proxies. Those are the same two
shapes as the historical corpus, at a site with different mechanics.

**This is not a vulnerability claim.** A CoW order's limit price and receiver are
enforced at settlement, so the value outcome is bounded no matter which contracts
execute. That is the design working. The point is what a defense can *see* at
signing time: the signed artifact governs the value bound and nothing else, while
the execution set is governed elsewhere and is mostly invisible.

Two bounds. `|T|` comes from settlement calldata, so contracts reached through
nested internal calls are invisible, making it a lower bound that works against
the finding rather than for it. And each window samples one day of blocks.

## Concessions (what would flip, and what the demo assumes)

These are load-bearing; do not quote the matrix without them.

- **The ladder is a coverage map, not a measurement.** The `un-defended` drain
  is a constant 1.00 USDC by construction. Rungs 1-4, 6 and 7 apply a policy to
  decoded/rendered fields (which is what clear-signing is); only rung 5 forks
  the chain. Rung 6 (signature simulation) is a *model* of net-transfer
  reasoning, not a second EVM run. The ladder does not query Blowfish/Blockaid;
  those are named as the capability each rung models. The one exception is the
  live GoPlus reputation lens above, which does query a real deployed service
  and is reported separately as measured.
- **F, and half of H, are caught by capabilities real wallets already have.**
  If you stop at an address-only allowlist, F and H look like bypasses. They are
  not, against a recipient-rendering, signature-scanning stack. The demo scores
  them at the rung that catches them, and does not claim they beat a 2026 stack.
- **E is a deterministic stand-in for a race.** In the wild the attacker must
  land the arming transaction between the wallet's simulation and inclusion (a
  same-block-before, or an upgradeable-proxy swap). The demo makes the ordering
  deterministic. E also assumes a pre-existing standing allowance to the router,
  and the "allowlisted router" is itself adversarial code.
- **G requires an under-hardened delegate.** `AAHelper.sweep` is callable by
  anyone. A genuinely hardened, trusted delegate gates its caller and is not
  drainable by a third party. So G demonstrates "the agent was induced to
  delegate to a malicious contract," where the allowlist entry is the poison,
  not "delegating to a trusted helper is unsafe." Real wallets (MetaMask, Rabby)
  also apply a categorical high-severity warning to *any* 7702 authorization,
  which the ladder models as L7.
- **Local anvil, mock contracts, free tokens.** MockUSDC, and minimal models of
  Permit2 (SignatureTransfer), a Seaport-style exchange, and a 7702 delegate.
  On-chain finality is real; economic loss is not. This is a mechanism demo.

## What this is and is not

It **is** a runnable enumeration of eight poisoned-tool drain shapes and a
per-capability coverage matrix, isolating the residue that a field-complete,
simulating clear-signing stack does not close: on-chain TOCTOU and categorical
authorization types, both leaning on an adversarial allowlisted target.

It is **not** a measurement, not a benchmark of any deployed product, and not a
claim that off-chain signatures defeat clear-signing in general. The one-line
version is: an address allowlist gates the counterparty, not the grant, and the
capabilities that close that gap are field rendering (for most of it) and
dynamic re-simulation plus type policy (for the rest).

## Where this sits

The pieces are known; the runnable capability map and the autonomous-signer
framing are the contribution.

- Closest prior statement of the residual is industry, not academia:
  Blockaid's "whitelist security gaps" and "Dissecting TOCTOU attacks" posts
  name recipient-substitution-to-an-allowlisted-target (our F), the TOCTOU
  simulation-evasion mechanism (our E), and malicious EIP-712 approvals. That
  work is qualitative, for human/treasury wallets, unmeasured and not composed
  into a coverage map, and not agent-scoped. This repo's delta is the runnable
  matrix, the capability ladder, and the autonomous-signer setting.
- The reasoning-vs-execution / intent-vs-calldata framing is named as an open
  problem in the agentic-commerce SoK ["T2T" attack, arXiv 2604.15367]. Related
  agent-security work: CrAIBench [2503.16248] injects at the memory/reasoning
  layer (the agent decides to send funds); "Your Agent Is Mine" [2604.08407]
  attacks malicious API intermediaries in the supply chain; MCPTox [2508.14925]
  measures MCP tool poisoning with no on-chain target. None evaluate wallet
  clear-signing / simulation defenses.
- On the specific rails: EIP-7702 phishing is measured on-chain in
  [arXiv 2512.12174] (single vector, no defense matrix); the reasoning/execution
  trust boundary is surveyed in [2601.04583] and [2605.16976]; agent-to-agent
  payment security in [2604.03733]; and human-facing signature legibility in
  "What I Sign Is Not What I See" [2601.16751].

## Layout

```
run.sh                one command: chain up, suite, coverage matrix
src/MockUSDC.sol      self-contained ERC-20 with EIP-2612 permit
src/Honeypot.sol      allowlisted router that arms after a benign dry-run (E)
src/Settlement.sol    allowlisted EIP-712 exchange, recipient set by the order (F)
src/AAHelper.sol      allowlisted EIP-7702 delegate that sweeps the account (G)
src/Permit2.sol       minimal universal-approval contract, SignatureTransfer (H)
demo/cast.py          stdlib wrappers over cast/forge (no web3 dep)
demo/chain.py         accounts, token, and the EIP-2612 / EIP-712 / 7702 / Permit2 signing
demo/attacks.py       the eight-drain suite
demo/reviewers.py     the capability ladder
demo/llm.py           optional live plan-review (frontier LLM + injection guardrail)
demo/goplus.py        optional live address-reputation lens (GoPlus Security API)
demo/source_tier.py   optional source-availability lens on the authority object (Etherscan)
demo/intent_gap.py    signed-order vs executed-contract gap in CoW settlements (Etherscan)
demo/race.py          quantifies the E residual: P(drain) = 1 - (1-beta)^K
demo/scorecard.py     run the suite, emit the coverage matrix
```

Optional keys (put in a gitignored `.env`; `run.sh` sources it): `GO_PLUS_APP_KEY`
+ `GO_PLUS_APP_SECRET` enable the live reputation lens; `ETHERSCAN_API_KEY`
enables the source-availability lens (free tier is 5 calls/sec, and its use
requires the "Powered by Etherscan.io APIs" attribution shown above);
`ANTHROPIC_API_KEY`
(+ `pip install anthropic`) and/or `LAKERA_GUARD_API_KEY` make the L1 plan-review
rung call a real model / guardrail.

[ERC-7730]: https://eips.ethereum.org/EIPS/eip-7730
["T2T" attack, arXiv 2604.15367]: https://arxiv.org/abs/2604.15367
[2503.16248]: https://arxiv.org/abs/2503.16248
[2604.08407]: https://arxiv.org/abs/2604.08407
[2508.14925]: https://arxiv.org/abs/2508.14925
[arXiv 2512.12174]: https://arxiv.org/abs/2512.12174
[2601.04583]: https://arxiv.org/abs/2601.04583
[2605.16976]: https://arxiv.org/abs/2605.16976
[2604.03733]: https://arxiv.org/abs/2604.03733
[2601.16751]: https://arxiv.org/abs/2601.16751
