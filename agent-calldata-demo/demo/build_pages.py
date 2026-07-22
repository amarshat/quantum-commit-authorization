#!/usr/bin/env python3
"""Generate the interactive GitHub Pages demo from out/scorecard.json.

The page embeds the scorecard the harness emits, so the interactive coverage
map cannot drift from the runnable results. Regenerate after ./run.sh with:

    python3 demo/build_pages.py

Writes ../docs/agent-drains-demo.html (relative to the repo root).
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DEMO_ROOT = os.path.dirname(HERE)                 # agent-calldata-demo/
REPO_ROOT = os.path.dirname(DEMO_ROOT)            # repo root
SCORECARD = os.path.join(DEMO_ROOT, "out", "scorecard.json")
OUT = os.path.join(REPO_ROOT, "docs", "agent-drains-demo.html")

TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Play the agent wallet-drain coverage map</title>
<meta name="description" content="Interactive: pick a poisoned-tool drain, watch an AI agent's benign English turn into malicious calldata, and toggle wallet defenses to see which one stops it and which survives.">
<style>
  :root{
    --bg:#ffffff; --fg:#1a1a1a; --muted:#5c6470; --line:#e6e8ec;
    --accent:#2f6feb; --accent-soft:#eaf1fe; --card:#f7f8fa; --code:#f2f3f5;
    --warn-bg:#fff8e6; --warn-line:#f0d98a; --ok:#1a7f4b; --bad:#c0392b;
    --ok-soft:#e7f5ec; --bad-soft:#fdecea;
  }
  @media (prefers-color-scheme: dark){
    :root{
      --bg:#0f1115; --fg:#e7e9ee; --muted:#9aa3b2; --line:#232733;
      --accent:#6ea0ff; --accent-soft:#16233f; --card:#161922; --code:#12151c;
      --warn-bg:#231d0e; --warn-line:#5a4a1e; --ok:#5ac088; --bad:#e57373;
      --ok-soft:#122019; --bad-soft:#241315;
    }
  }
  :root[data-theme="light"]{ --bg:#ffffff; --fg:#1a1a1a; --muted:#5c6470; --line:#e6e8ec; --accent:#2f6feb; --accent-soft:#eaf1fe; --card:#f7f8fa; --code:#f2f3f5; --warn-bg:#fff8e6; --warn-line:#f0d98a; --ok:#1a7f4b; --bad:#c0392b; --ok-soft:#e7f5ec; --bad-soft:#fdecea; }
  :root[data-theme="dark"]{ --bg:#0f1115; --fg:#e7e9ee; --muted:#9aa3b2; --line:#232733; --accent:#6ea0ff; --accent-soft:#16233f; --card:#161922; --code:#12151c; --warn-bg:#231d0e; --warn-line:#5a4a1e; --ok:#5ac088; --bad:#e57373; --ok-soft:#122019; --bad-soft:#241315; }
  *{box-sizing:border-box}
  body{margin:0; background:var(--bg); color:var(--fg); font:17px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; -webkit-font-smoothing:antialiased; overflow-x:hidden;}
  .wrap{max-width:860px; margin:0 auto; padding:0 22px}
  header{padding:56px 0 24px; border-bottom:1px solid var(--line)}
  h1{font-size:2.0rem; line-height:1.2; margin:0 0 14px; letter-spacing:-0.02em}
  .lede{font-size:1.14rem; color:var(--muted); margin:0}
  .meta{margin-top:20px; display:flex; flex-wrap:wrap; gap:8px}
  .pill{font-size:.82rem; padding:4px 11px; border:1px solid var(--line); border-radius:999px; color:var(--muted); text-decoration:none}
  .pill:hover{border-color:var(--accent); color:var(--accent)}
  .nav{border-bottom:1px solid var(--line); background:var(--bg); position:sticky; top:0; z-index:20}
  .navwrap{display:flex; align-items:center; justify-content:space-between; gap:10px; padding-top:11px; padding-bottom:11px}
  .brand{font-weight:800; font-size:.92rem; text-decoration:none; color:var(--fg); letter-spacing:-0.01em; white-space:nowrap}
  .navlinks{display:flex; flex-wrap:wrap; gap:2px}
  .navlinks a{font-size:.85rem; text-decoration:none; color:var(--muted); padding:5px 9px; border-radius:8px; white-space:nowrap}
  .navlinks a:hover{color:var(--accent); background:var(--accent-soft)}
  .navlinks a[aria-current="page"]{color:var(--accent); background:var(--accent-soft); font-weight:650}
  a{color:var(--accent)}
  h2{font-size:1.34rem; margin:44px 0 8px; letter-spacing:-0.01em}
  p{margin:12px 0}
  .muted{color:var(--muted)}
  code{background:var(--code); padding:1px 5px; border-radius:5px; font-size:.9em; font-family:"SF Mono",ui-monospace,Menlo,Consolas,monospace}

  /* picker */
  .picker{display:flex; flex-wrap:wrap; gap:8px; margin:18px 0 6px}
  .drainbtn{border:1px solid var(--line); background:var(--card); color:var(--fg); border-radius:10px; padding:8px 12px; cursor:pointer; font:inherit; font-size:.88rem; display:flex; align-items:center; gap:8px; line-height:1.2}
  .drainbtn .k{font-weight:800; color:var(--muted)}
  .drainbtn:hover{border-color:var(--accent)}
  .drainbtn[aria-pressed="true"]{border-color:var(--accent); background:var(--accent-soft); color:var(--fg)}
  .drainbtn[aria-pressed="true"] .k{color:var(--accent)}

  /* flow */
  .flow{margin:14px 0 6px; display:flex; flex-direction:column; gap:10px}
  .frow{background:var(--card); border:1px solid var(--line); border-radius:12px; padding:16px 18px; display:flex; gap:16px; align-items:flex-start}
  .frow .lab{font-size:.72rem; letter-spacing:1.5px; text-transform:uppercase; color:var(--muted); font-weight:700; width:96px; flex-shrink:0; padding-top:3px}
  .frow .body{flex:1; min-width:0}
  .frow .plain{font-size:1.05rem; font-weight:600; overflow-wrap:anywhere}
  .frow .mono{font-family:"SF Mono",ui-monospace,Menlo,Consolas,monospace; font-size:.98rem; word-break:break-word}
  .mono .bad{color:var(--bad); font-weight:700}
  .mono .amt{color:#b8860b; font-weight:700}
  .mono .ok{color:var(--ok); font-weight:700}
  .frow .sub{font-size:.86rem; color:var(--muted); margin-top:4px}
  .tag{font-size:.72rem; font-weight:700; padding:5px 10px; border-radius:999px; flex-shrink:0; white-space:nowrap}
  .tag.pass{background:var(--ok-soft); color:var(--ok); border:1px solid var(--ok)}
  .tag.fail{background:var(--bad-soft); color:var(--bad); border:1px solid var(--bad)}

  /* defenses */
  .defenses{margin-top:22px}
  .drow{display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:12px; margin-bottom:4px}
  .drow h2{margin:0}
  .quick{display:flex; gap:8px}
  .qbtn{border:1px solid var(--line); background:none; color:var(--muted); border-radius:8px; padding:5px 10px; cursor:pointer; font:inherit; font-size:.8rem}
  .qbtn:hover{border-color:var(--accent); color:var(--accent)}
  .rungs{display:flex; flex-direction:column; gap:6px; margin-top:10px}
  .rung{display:flex; align-items:center; gap:12px; border:1px solid var(--line); border-radius:10px; padding:10px 14px; cursor:pointer; user-select:none}
  .rung:hover{border-color:var(--accent)}
  .rung .sw{width:38px; height:22px; border-radius:999px; background:var(--line); position:relative; flex-shrink:0; transition:background .12s}
  .rung .sw::after{content:""; position:absolute; top:2px; left:2px; width:18px; height:18px; border-radius:50%; background:#fff; transition:left .12s}
  .rung[aria-checked="true"] .sw{background:var(--accent)}
  .rung[aria-checked="true"] .sw::after{left:18px}
  .rung .name{flex:1; min-width:0; font-size:.96rem}
  .rung .name b{font-weight:700}
  .rung .rn{font-size:.72rem; color:var(--muted); font-weight:700; width:26px}
  .rung .res{font-size:.8rem; font-weight:700; white-space:nowrap}
  .rung .res.veto{color:var(--ok)}
  .rung .res.blind{color:var(--muted)}
  .rung.off{opacity:.5}
  .rung.off .res{visibility:hidden}

  /* verdict */
  .verdict{margin-top:20px; border-radius:14px; padding:18px 20px; border:1px solid}
  .verdict.stopped{background:var(--ok-soft); border-color:var(--ok)}
  .verdict.drained{background:var(--bad-soft); border-color:var(--bad)}
  .verdict .big{font-size:1.15rem; font-weight:800}
  .verdict.stopped .big{color:var(--ok)}
  .verdict.drained .big{color:var(--bad)}
  .verdict .why{margin-top:6px; font-size:.95rem; color:var(--fg); overflow-wrap:anywhere}

  /* summary map */
  .maprow{display:grid; grid-template-columns:26px minmax(0,1fr) auto; gap:10px; align-items:center; padding:9px 4px; border-bottom:1px solid var(--line); cursor:pointer}
  .maprow:hover{background:var(--card)}
  .maprow .k{font-weight:800; color:var(--muted)}
  .maprow .lbl{font-size:.95rem}
  .maprow .at{font-size:.82rem; font-weight:700; white-space:nowrap}
  .at.ok{color:var(--ok)} .at.res{color:var(--bad)} .at.cat{color:#b8860b}

  footer{margin:52px 0 44px; padding-top:20px; border-top:1px solid var(--line); color:var(--muted); font-size:.9rem}
</style>
</head>
<body>
<nav class="nav"><div class="wrap navwrap">
  <a class="brand" href="index.html">Quantum-Commit Auth</a>
  <div class="navlinks">
    <a href="index.html">Overview</a>
    <a href="agent-drains.html">Agent drains</a>
    <a href="agent-drains-demo.html" aria-current="page">Play it</a>
    <a href="https://github.com/amarshat/quantum-commit-authorization">GitHub</a>
  </div>
</div></nav>
<div class="wrap">
<header>
  <h1>Play the agent wallet-drain map</h1>
  <p class="lede">An AI agent decides in English but signs bytes. Pick a poisoned-tool drain, watch the benign sentence become malicious calldata, then switch on wallet defenses one at a time and see which one stops it, and the one that survives them all.</p>
  <div class="meta">
    <a class="pill" href="agent-drains.html">Read the write-up</a>
    <a class="pill" href="https://doi.org/10.5281/zenodo.21470174">Paper (Zenodo DOI)</a>
    <a class="pill" href="https://github.com/amarshat/quantum-commit-authorization/tree/main/agent-calldata-demo">Run it yourself</a>
  </div>
</header>

<h2>1. Pick a drain</h2>
<div class="picker" id="picker"></div>
<p class="muted" id="drainTitle" style="margin-top:4px"></p>

<div class="flow" id="flow"></div>

<div class="defenses">
  <div class="drow">
    <h2>2. Turn on wallet defenses</h2>
    <div class="quick">
      <button class="qbtn" id="qEnglish">English only</button>
      <button class="qbtn" id="qFull">Full stack</button>
    </div>
  </div>
  <p class="muted" style="margin:6px 0 0">A wallet is a stack of capabilities, weakest first. Each is the <em>lowest</em> rung that can stop a given drain; toggle them and watch the verdict.</p>
  <div class="rungs" id="rungs"></div>
</div>

<div class="verdict" id="verdict"></div>

<h2>The whole map</h2>
<p class="muted">Every drain, and the cheapest capability that stops it. Click a row to load it above. <code>&dagger;</code> marks a blunt categorical warning, not a targeted stop.</p>
<div id="map"></div>

<footer>
  Generated from the harness's <code>out/scorecard.json</code>, so this page shows the same result the runnable code produces. Nothing here is a new attack; it is a minimum-capability stop-map with its one true residual named. Source and short note linked above.
</footer>
</div>

<script>
const DATA = __SCORECARD_JSON__;

const RUNG_LABELS = [
  null,
  ["plan-review", "reads the English plan, never the bytes"],
  ["address allowlist", "decode the action, veto an un-allowlisted counterparty"],
  ["amount-aware clear-sign", "also veto unlimited amounts"],
  ["recipient rendering", "also render the ultimate recipient (an order's taker)"],
  ["tx simulation", "fork-run the tx, veto on adverse state diff"],
  ["signature simulation", "reason about the net transfer a signature enables"],
  ["tx-type policy", "categorical warning on dangerous action types"],
];

function shortAddr(a){ if(!a || a.length < 12) return a; return a.slice(0,6) + "…" + a.slice(-4); }
function shortenAddrs(s){ return s.replace(/0x[a-fA-F0-9]{40}/g, m => shortAddr(m)); }
function fmtAmount(amt){
  if(amt === "UNLIMITED") return "UNLIMITED";
  if(amt === "account")   return "entire account";
  const n = Number(amt);
  if(!isNaN(n)) return (n/1e6).toLocaleString(undefined,{minimumFractionDigits:2}) + " USDC";
  return amt;
}
// Build the "signed" mono line + whether it is broadcast or an off-chain signature.
function signedView(d){
  const cp = shortAddr(d.counterparty), rc = shortAddr(d.recipient);
  const amt = fmtAmount(d.amount);
  const stranger = (d.recipient === "0x90F79bf6EB2c4f870365E785982E1f101E93b906");
  const A = s => `<span class="bad">${s}</span>`;      // attacker / dangerous target
  const AMT = s => `<span class="amt">${s}</span>`;     // dangerous amount
  const OK = s => `<span class="ok">${s}</span>`;       // allowlisted / benign-looking
  switch(d.action_type){
    case "transfer":  return {line:`transfer(${A(rc)}, ${amt})`, off:false, sub:"a stranger's address in the payee slot, not the merchant's"};
    case "approve":   return {line:`approve(${A(cp)}, ${AMT(amt)})`, off:false, sub:"unlimited allowance to a stranger, not the router"};
    case "permit":    return stranger
                        ? {line:`permit → spender ${A(cp)}, ${AMT(amt)}`, off:true, sub:"off-chain signature to a stranger; nothing is broadcast when the agent signs"}
                        : {line:`permit → spender ${OK(cp)} <em>(allowlisted)</em>, ${AMT(amt)}`, off:true, sub:"the spender is allowed; the danger is the unlimited grant, drained later"};
    case "call":      return {line:`${OK(cp)}<em>(allowlisted)</em>.swap(…)`, off:false, sub:"a benign no-op at simulation; the attacker arms the contract only after the check"};
    case "order":     return {line:`EIP-712 order → exchange ${OK(cp)} <em>(allowlisted)</em>, taker ${A(rc)}`, off:true, sub:"the counterparty is allowed; the order's recipient field is the attacker"};
    case "delegation":return {line:`EIP-7702 authorize(delegate ${OK(cp)} <em>(allowlisted)</em>)`, off:true, sub:"no amount, no transaction; it hands the whole account to code that then sweeps it"};
    case "permit2_approve": return {line:`approve(Permit2 ${OK(cp)} <em>(allowlisted)</em>, ${AMT(amt)})`, off:false, sub:"the approval itself is benign; a later poisoned Permit2 signature does the draining"};
    default:          return {line:`${d.action_type}(${A(cp)}, ${amt})`, off:false, sub:""};
  }
}

let sel = 0;
let enabled = new Set([1,2,3,4,5,6,7]);

const picker = document.getElementById("picker");
DATA.forEach((d,i)=>{
  const b = document.createElement("button");
  b.className = "drainbtn"; b.setAttribute("aria-pressed", i===0);
  b.innerHTML = `<span class="k">${d.id[0]}</span> ${d.id.split("-").slice(1).join("-")}`;
  b.onclick = ()=>{ sel=i; render(); };
  picker.appendChild(b);
});

function evaluate(d){
  // lowest enabled rung whose verdict vetoes
  let stop = null;
  for(const v of d.verdicts){
    if(enabled.has(v.rung) && v.veto){ stop = v; break; }
  }
  return stop; // null => drained
}

function render(){
  const d = DATA[sel];
  [...picker.children].forEach((b,i)=>b.setAttribute("aria-pressed", i===sel));
  document.getElementById("drainTitle").textContent = d.title;

  // flow
  const sv = signedView(d);
  const l1 = d.verdicts.find(v=>v.rung===1);
  const englishOn = enabled.has(1);
  const flow = document.getElementById("flow");
  flow.innerHTML = `
    <div class="frow">
      <div class="lab">Agent said</div>
      <div class="body"><div class="plain">${d.stated_intent}</div></div>
      ${englishOn ? `<span class="tag pass">plan review: PASS</span>` : ``}
    </div>
    <div class="frow">
      <div class="lab">Agent signed</div>
      <div class="body"><div class="mono">${sv.line}</div><div class="sub">${sv.off ? "off-chain signature · " : "on-chain calldata · "}${sv.sub}</div></div>
    </div>
    <div class="frow">
      <div class="lab">On chain</div>
      <div class="body"><div class="plain" style="color:var(--bad)">${shortenAddrs(d.true_effect)}</div></div>
      <span class="tag fail">irreversible</span>
    </div>`;

  // rungs
  const rungs = document.getElementById("rungs");
  rungs.innerHTML = "";
  for(let r=1;r<=7;r++){
    const on = enabled.has(r);
    const v = d.verdicts.find(x=>x.rung===r);
    const row = document.createElement("div");
    row.className = "rung" + (on?"":" off");
    row.setAttribute("aria-checked", on);
    const [nm, desc] = RUNG_LABELS[r];
    let resHtml = "";
    if(on){
      resHtml = v.veto
        ? `<span class="res veto">✓ vetoes</span>`
        : `<span class="res blind">blind</span>`;
    }
    row.innerHTML = `<span class="rn">L${r}</span><span class="sw"></span>
      <span class="name"><b>${nm}</b> <span class="muted">— ${desc}</span></span>${resHtml}`;
    row.onclick = ()=>{ if(enabled.has(r)) enabled.delete(r); else enabled.add(r); render(); };
    rungs.appendChild(row);
  }

  // verdict
  const stop = evaluate(d);
  const vd = document.getElementById("verdict");
  if(stop){
    vd.className = "verdict stopped";
    vd.innerHTML = `<div class="big">Stopped at L${stop.rung} · ${stop.name}</div>
      <div class="why">${shortenAddrs(stop.reason)}.</div>`;
  } else {
    const anyRung = d.verdicts.some(v=>v.veto);
    const note = anyRung
      ? "None of the defenses you have on catch it. Turn on the rung that does, above."
      : "This drain survives the full ladder. The malicious state does not exist when the wallet looks; only re-simulation at the moment of inclusion catches it, which a machine-speed agent signing many actions cannot rely on.";
    vd.className = "verdict drained";
    vd.innerHTML = `<div class="big">Drained · ${fmtAmount(d.amount)} gone</div>
      <div class="why">${note}</div>`;
  }
}

// quick buttons
document.getElementById("qEnglish").onclick = ()=>{ enabled = new Set([1]); render(); };
document.getElementById("qFull").onclick    = ()=>{ enabled = new Set([1,2,3,4,5,6,7]); render(); };

// summary map
const map = document.getElementById("map");
DATA.forEach((d,i)=>{
  const row = document.createElement("div");
  row.className = "maprow";
  let atClass = "ok", atText = "L"+d.caught_at+" "+d.caught_name;
  if(d.caught_at === null){ atClass="res"; atText="survives all 7"; }
  else if(d.caught_at === 7){ atClass="cat"; atText="L7 "+d.caught_name+" †"; }
  row.innerHTML = `<span class="k">${d.id[0]}</span>
    <span class="lbl">${d.title}</span>
    <span class="at ${atClass}">${atText}</span>`;
  row.onclick = ()=>{ sel=i; enabled=new Set([1,2,3,4,5,6,7]); render(); window.scrollTo({top:0,behavior:"smooth"}); };
  map.appendChild(row);
});

render();
</script>
</body>
</html>
"""


def main():
    with open(SCORECARD) as f:
        data = json.load(f)
    # keep only the fields the page uses, small and stable
    slim = []
    for a in data:
        slim.append({
            "id": a["id"],
            "title": a["title"],
            "stated_intent": a["stated_intent"],
            "true_effect": a["true_effect"],
            "action_type": a["action_type"],
            "counterparty": a["counterparty"],
            "recipient": a["recipient"],
            "amount": a["amount"],
            "caught_at": a["caught_at"],
            "caught_name": a["caught_name"],
            "verdicts": [
                {"rung": v["rung"], "name": v["name"], "veto": v["veto"], "reason": v["reason"]}
                for v in a["verdicts"]
            ],
        })
    html = TEMPLATE.replace("__SCORECARD_JSON__", json.dumps(slim, ensure_ascii=False))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        f.write(html)
    print("wrote", OUT, "(", len(slim), "drains )")


if __name__ == "__main__":
    main()
