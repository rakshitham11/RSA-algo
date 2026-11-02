const $ = id => document.getElementById(id);
let state = { enc: null };

async function api(path, body) {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json();
  if (!data.ok) throw new Error(data.error);
  return data;
}
function setProgress(upTo) {
  document.querySelectorAll("#flow li").forEach(li => li.classList.toggle("done", +li.dataset.s <= upTo));
  $("progress").style.width = (upTo / 8 * 100) + "%";
}
function showError(msg) { $("error").textContent = msg || ""; $("error").hidden = !msg; }
function toast(msg) { const t = $("toast"); t.textContent = msg; t.classList.add("show"); setTimeout(() => t.classList.remove("show"), 2600); }
const pq = () => ({ p: $("p").value, q: $("q").value, e: $("e").value });
const esc = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const vis = c => (c === " " ? "␣" : esc(c));
const row = cells => "<tr>" + cells.map(c => `<td>${c}</td>`).join("") + "</tr>";

function renderKeys(k) {
  const items = [["p", k.p], ["q", k.q], ["n = p × q", k.n], ["φ(n)", k.phi], ["e", k.e], ["d", k.d],
    ["Public key (e, n)", `(${k.e}, ${k.n})`], ["Private key (d, n)", `(${k.d}, ${k.n})`]];
  $("keyGrid").innerHTML = items.map(([a, b]) => `<div><small>${a}</small><b>${b}</b></div>`).join("");
  $("keyMath").textContent = `n = ${k.p} × ${k.q} = ${k.n};  φ(n) = ${k.p - 1} × ${k.q - 1} = ${k.phi};  ${k.check}`;
  $("keyCard").hidden = false;
}

async function guard(fn) {
  showError("");
  try { await fn(); } catch (e) { showError(e.message); }
}

// Live check of e against the current primes (client-side hint; server is the authority)
const gcd = (a, b) => { while (b) [a, b] = [b, a % b]; return a; };
const isPrime = n => { if (n < 2) return false; for (let i = 2; i * i <= n; i++) if (n % i === 0) return false; return true; };
function checkE() {
  const hint = $("eHint"), raw = $("e").value.trim();
  document.querySelectorAll("#presets button").forEach(b => b.classList.toggle("on", b.dataset.e === raw));
  hint.className = "hint";
  if (!raw) { hint.textContent = "e will be chosen automatically."; return; }
  const e = Number(raw), p = Number($("p").value), q = Number($("q").value);
  if (!Number.isInteger(e)) { hint.textContent = "e must be a whole number."; hint.classList.add("bad"); return; }
  if (!(isPrime(p) && isPrime(q) && p !== q)) { hint.textContent = "Enter two distinct primes to check e."; return; }
  const phi = (p - 1) * (q - 1), g = gcd(e, phi);
  let msg = "";
  if (e <= 1) msg = `Invalid: e must be greater than 1.`;
  else if (e >= phi) msg = `Invalid: e must be smaller than φ(n) = ${phi}.`;
  else if (g !== 1) msg = `Invalid: gcd(${e}, ${phi}) = ${g}, it must be 1.`;
  hint.textContent = msg || `Valid: 1 < ${e} < ${phi} and gcd(${e}, ${phi}) = 1.`;
  hint.classList.add(msg ? "bad" : "good");
}
$("presets").onclick = ev => { const b = ev.target.closest("button"); if (b) { $("e").value = b.dataset.e; checkE(); } };
["e", "p", "q"].forEach(id => $(id).addEventListener("input", checkE));

$("btnKeys").onclick = () => guard(async () => {
  const { keys } = await api("/api/keys", pq());
  state.enc = null; renderKeys(keys); setProgress(2);
  $("encCard").hidden = $("decCard").hidden = true;
});

$("btnRandom").onclick = () => guard(async () => {
  const { keys } = await api("/api/keys", { random: true });
  $("p").value = keys.p; $("q").value = keys.q; $("e").value = ""; checkE();
  state.enc = null; renderKeys(keys); setProgress(2);
  $("encCard").hidden = $("decCard").hidden = true;
});

$("btnEnc").onclick = () => guard(async () => {
  const r = await api("/api/encrypt", { ...pq(), plaintext: $("plain").value });
  state.enc = { ...pq(), cipher: r.cipher };
  renderKeys(r.keys);
  $("mapOut").innerHTML = r.steps.map(s => `<span class="chip"><b>${vis(s.char)}</b>= ${s.m}</span>`).join("");
  $("numSeq").textContent = "ASCII sequence: " + r.numbers.join(" ");
  $("pubUsed").textContent = `Public key (e, n) = (${r.keys.e}, ${r.keys.n})`;
  $("encTable").innerHTML = "<tr><th>Char</th><th>M</th><th>Calculation</th><th>C</th></tr>" +
    r.steps.map(s => row([vis(s.char), s.m, `${s.formula}`, `<b>${s.c}</b>`])).join("");
  $("cipherOut").textContent = r.cipher.join(" ");
  $("encStatus").textContent = `Encryption complete: ${r.cipher.length} values encrypted.`;
  $("mapCard").hidden = $("encCard").hidden = false; $("decCard").hidden = true;
  setProgress(5);
});

$("btnDec").onclick = () => guard(async () => {
  if (!state.enc) throw new Error("Encrypt a message first, then decrypt it.");
  const r = await api("/api/decrypt", state.enc);
  $("privUsed").textContent = `Private key (d, n) = (${r.keys.d}, ${r.keys.n})`;
  $("decTable").innerHTML = "<tr><th>C</th><th>Calculation</th><th>M</th><th>Char</th></tr>" +
    r.steps.map(s => row([s.c, s.formula, `<b>${s.m}</b>`, vis(s.char)])).join("");
  $("decNums").textContent = r.numbers.join(" ");
  $("recovered").textContent = r.plaintext;
  const expected = $("plain").value;
  const match = r.plaintext === expected;
  $("decStatus").textContent = match ? "Decryption successful: the recovered text matches the original message." : "Recovered text differs from the original.";
  $("decCard").hidden = false; setProgress(8);
  if (match) toast("Decryption successful");
});

$("btnCopy").onclick = async () => {
  try { await navigator.clipboard.writeText($("cipherOut").textContent); toast("Encrypted output copied"); }
  catch { showError("Copy failed. Select the text and copy it manually."); }
};

$("btnClear").onclick = () => {
  $("p").value = 61; $("q").value = 53; $("e").value = ""; checkE(); $("plain").value = ""; state.enc = null; showError("");
  ["keyCard", "mapCard", "encCard", "decCard"].forEach(i => $(i).hidden = true); setProgress(0);
};
setProgress(0);
checkE();
