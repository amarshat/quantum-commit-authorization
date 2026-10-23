#!/usr/bin/env python3
"""Enumerate every input an includer controls, from the pinned sources.

The binding-completeness argument needs the list of fields a bundler or
sequencer can choose, and a hand-written list already missed one
(preVerificationGas). This script derives the list instead:

  ERC-4337   every field of PackedUserOperation; each packed field replaced by
             the subfields EntryPoint v0.8 unpacks from it (UserOperationLib's
             unpack* functions, plus the paymaster data after the static
             paymaster fields); and every argument of EntryPoint.handleOps
             other than the operations themselves.
  zkSync     every field of the Era Transaction struct.

It then checks coverage. Each 4337 input must have a test named
test_field_<name> in contracts/test/BindingSurface4337.t.sol, which measures
the input rather than asserting it. Each zkSync field must have a class in
binding/zksync.json whose evidence pattern occurs in the account source, and a
field classed not_read must not be read by the account or by any
TransactionHelper function the account calls.

    python3 binding/enumerate.py

Reads only committed and pinned sources (contracts-zksync needs `npm ci`).
Writes binding/results/fields.json; exits non-zero on any gap.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AA = ROOT / "contracts" / "lib" / "account-abstraction" / "contracts"
STRUCT_4337 = AA / "interfaces" / "PackedUserOperation.sol"
OPLIB = AA / "core" / "UserOperationLib.sol"
ENTRYPOINT = AA / "core" / "EntryPoint.sol"
HARNESS = ROOT / "contracts" / "test" / "BindingSurface4337.t.sol"
ZK_LIB = (ROOT / "contracts-zksync" / "node_modules" / "@matterlabs" / "zksync-contracts" / "contracts"
          / "system-contracts" / "libraries" / "TransactionHelper.sol")
ZK_ACCOUNT = ROOT / "contracts-zksync" / "src" / "QCAAccountZkSync.sol"
ZK_TABLE = ROOT / "binding" / "zksync.json"
OUT = ROOT / "binding" / "results" / "fields.json"


def strip_comments(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def struct_fields(path, name):
    src = strip_comments(path.read_text())
    body = re.search(r"struct\s+" + name + r"\s*\{(.*?)\}", src, re.S)
    if not body:
        sys.exit(f"struct {name} not found in {path}")
    return [re.split(r"\s+", d.strip())[-1] for d in body.group(1).split(";") if d.strip()]


def functions(src):
    """name -> body for every function in a Solidity source."""
    out = {}
    for m in re.finditer(r"function\s+(\w+)\s*\(", src):
        i = src.find("{", m.end())
        semi = src.find(";", m.end())
        if i < 0 or (0 <= semi < i):
            continue
        depth, j = 0, i
        while True:
            depth += {"{": 1, "}": -1}.get(src[j], 0)
            if depth == 0:
                break
            j += 1
        out[m.group(1)] = src[i:j + 1]
    return out


def lower_first(s):
    return s[0].lower() + s[1:]


def inputs_4337():
    fields = struct_fields(STRUCT_4337, "PackedUserOperation")
    lib = strip_comments(OPLIB.read_text())
    subfields = {}
    for name, body in functions(lib).items():
        m = re.fullmatch(r"unpack(\w+)", name)
        if not m or m.group(1) in ("Uints", "High128", "Low128", "PaymasterStaticFields"):
            continue
        parent = re.search(r"userOp\.(\w+)", body)
        if parent:
            sub = lower_first(m.group(1))
            subfields.setdefault(parent.group(1), []).append(sub)
    # paymasterAndData = paymaster (20 bytes) | two gas limits | paymaster data.
    static = re.search(r"function\s+unpackPaymasterStaticFields\s*\(.*?returns\s*\((.*?)\)", lib, re.S)
    if not static or "PAYMASTER_DATA_OFFSET" not in lib:
        sys.exit("paymasterAndData layout not found in UserOperationLib")
    pm_names = [re.split(r"\s+", d.strip())[-1] for d in static.group(1).split(",")]
    pm = subfields.setdefault("paymasterAndData", [])
    for n in pm_names:
        if n == "paymaster" and n not in pm:
            pm.insert(0, n)
    pm.append("paymasterData")

    out = []
    for f in fields:
        out += subfields.get(f, [f])
    ep = strip_comments(ENTRYPOINT.read_text())
    sig = re.search(r"function\s+handleOps\s*\((.*?)\)", ep, re.S).group(1)
    for d in sig.split(","):
        name = re.split(r"\s+", d.strip())[-1]
        if name != "ops":
            out.append(name)
    return fields, subfields, out


def check_4337(inputs):
    src = strip_comments(HARNESS.read_text())
    tests = set(re.findall(r"function\s+test_field_(\w+)\s*\(", src))
    return [f"4337: no test_field_{i} in {HARNESS.relative_to(ROOT)}" for i in inputs if i not in tests]


def check_zksync():
    if not ZK_LIB.exists():
        return [], [f"zksync: {ZK_LIB.relative_to(ROOT)} missing; run npm ci in contracts-zksync"]
    fields = struct_fields(ZK_LIB, "Transaction")
    table = json.loads(ZK_TABLE.read_text())["fields"]
    account = strip_comments(ZK_ACCOUNT.read_text())
    helpers = functions(strip_comments(ZK_LIB.read_text()))
    called = [h for h in helpers if re.search(r"\.\s*" + h + r"\s*\(", account)]
    errors = []
    for f in fields:
        row = table.get(f)
        if row is None:
            errors.append(f"zksync: field {f} has no class in {ZK_TABLE.relative_to(ROOT)}")
            continue
        if row["evidence"] and not re.search(row["evidence"], account):
            errors.append(f"zksync: evidence for {f} not found in the account")
        if row["class"] == "not_read":
            pat = r"transaction\." + f + r"\b"
            if re.search(pat, account):
                errors.append(f"zksync: {f} is classed not_read but the account reads it")
            for h in called:
                if re.search(r"_transaction\." + f + r"\b", helpers[h]):
                    errors.append(f"zksync: {f} is classed not_read but {h} reads it")
    for f in table:
        if f not in fields:
            errors.append(f"zksync: {f} is in the table but not in the pinned struct")
    return [{"field": f, **table.get(f, {})} for f in fields] + [{"helpers_called": called}], errors


def main():
    fields, subfields, inputs = inputs_4337()
    errors = check_4337(inputs)
    zk, zk_errors = check_zksync()
    errors += zk_errors
    out = {
        "erc4337": {"struct_fields": fields, "unpacked": subfields, "inputs": inputs,
                    "harness": str(HARNESS.relative_to(ROOT))},
        "zksync": zk,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1) + "\n")
    print(f"4337: {len(fields)} struct fields -> {len(inputs)} includer inputs")
    print(f"zksync: {sum(1 for r in zk if 'field' in r)} struct fields")
    for e in errors:
        print("GAP", e)
    if errors:
        sys.exit(1)
    print(f"no gaps; wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
