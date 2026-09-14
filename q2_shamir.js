/*
 * INTE2639 Cloud Security - Assignment 3, Question 2(4)
 * Shamir's (3,4) threshold secret sharing over a prime field.
 *
 * Student: Phyu Phyu Shinn Thant (Zyra)
 * Student ID: s4022136
 */

"use strict";

// ---------------------------------------------------------------------
// 1. PARAMETERS
// ---------------------------------------------------------------------
const SECRET = BigInt(
  "65321184733616076672370148945763738498149232595568463912401977781329025278286985500073457152337085634874598346444012164240877343996274357630054838119140256050304779195289665435836965316022830185373644775598491178306337590274810794613511248738792136130718957593137729353005520315703479830923888713801964866318"
);

const PRIME = BigInt(
  "179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224137859"
);

const a0 = SECRET;                 
const a1 = 4022136n;               
const a2 = BigInt(                  
  "125488864845486690302565925011400227811432265211279874674601982144835097358668815383759947244301064040053758969848053733144308014815990408196605184427654958240059613827074261142774052663557160446535119179869676457106783502482112332774776487837071661503387415181676733927009648511597844154915832802233701085228"
);

const N_SHARES = 4;
const THRESHOLD = 3; 

// ---------------------------------------------------------------------
// 2. MODULAR ARITHMETIC HELPERS
// ---------------------------------------------------------------------
function mod(a, m) {
  return ((a % m) + m) % m;
}

function modInverse(a, m) {
  a = mod(a, m);
  let [oldR, r] = [a, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error("no modular inverse exists");
  return mod(oldS, m);
}

// ---------------------------------------------------------------------
// 3. SHARE GENERATION
// ---------------------------------------------------------------------
function evaluatePolynomial(x) {
  return mod(mod(a2 * x + a1, PRIME) * x + a0, PRIME);
}

function generateShares() {
  const shares = [];
  for (let i = 1n; i <= BigInt(N_SHARES); i++) {
    shares.push({ x: i, y: evaluatePolynomial(i) });
  }
  return shares;
}

// ---------------------------------------------------------------------
// 4. SECRET RECONSTRUCTION
// ---------------------------------------------------------------------
function reconstruct(selected) {
  let secret = 0n;
  for (let i = 0; i < selected.length; i++) {
    let numerator = 1n;
    let denominator = 1n;
    for (let j = 0; j < selected.length; j++) {
      if (i === j) continue;
      numerator = mod(numerator * -selected[j].x, PRIME);
      denominator = mod(denominator * (selected[i].x - selected[j].x), PRIME);
    }
    const basis = mod(numerator * modInverse(denominator, PRIME), PRIME);
    secret = mod(secret + selected[i].y * basis, PRIME);
  }
  return secret;
}

function combinations(arr, k) {
  const out = [];
  (function pick(start, chosen) {
    if (chosen.length === k) { out.push([...chosen]); return; }
    for (let i = start; i < arr.length; i++) {
      chosen.push(arr[i]);
      pick(i + 1, chosen);
      chosen.pop();
    }
  })(0, []);
  return out;
}

// ---------------------------------------------------------------------
// 5. RUN
// ---------------------------------------------------------------------

function main() {
  const line = "=".repeat(72);

  console.log(line);
  console.log("SHAMIR (3,4) SECRET SHARING - PAILLIER LAMBDA RECOVERY");
  console.log(line);
  console.log("Secret (lambda) bit length :", SECRET.toString(2).length);
  console.log("Prime modulus bit length   :", PRIME.toString(2).length);
  console.log("Prime > secret             :", PRIME > SECRET);
  console.log("Polynomial degree          :", THRESHOLD - 1);
  console.log("Shares generated           :", N_SHARES);
  console.log("Shares needed to recover   :", THRESHOLD);
  console.log();
  console.log("f(x) = a0 + a1*x + a2*x^2  (mod PRIME)");
  console.log("  a0 = lambda  (the secret)");
  console.log("  a1 =", a1.toString(), " (student ID)");
  console.log("  a2 = random 1024-bit value");
  console.log();

  // ---- Part (2): divide into 4 shares -----------------------------
  console.log(line);
  console.log("PART 2 - GENERATE 4 SHARES (one per cloud provider)");
  console.log(line);
  const shares = generateShares();
  shares.forEach((s, idx) => {
    console.log(`\nCloud ${idx + 1}  ->  Share ${s.x}`);
    console.log(`  x = ${s.x}`);
    console.log(`  y = ${s.y}`);
  });
  console.log();

  // ---- Part (3): recover from any 3 -------------------------------
  console.log(line);
  console.log("PART 3 - RECOVER THE SECRET FROM ANY 3 OF 4 SHARES");
  console.log(line);
  const subsets = combinations(shares, THRESHOLD);
  let allOk = true;
  for (const subset of subsets) {
    const ids = subset.map((s) => Number(s.x)).join(", ");
    const recovered = reconstruct(subset);
    const ok = recovered === SECRET;
    if (!ok) allOk = false;
    console.log(`  Shares {${ids}}  ->  ${ok ? "RECOVERED CORRECTLY" : "FAILED"}`);
  }
  console.log(`\nAll ${subsets.length} three-share combinations succeeded: ${allOk}`);
  console.log();

  // ---- Part (5): what two colluding clouds learn ------------------
  console.log(line);
  console.log("PART 5 - SECURITY WHEN 2 OF 4 CLOUDS COLLUDE");
  console.log(line);
  console.log("Two shares give two equations in three unknowns (a0, a1, a2).");
  console.log("The system is underdetermined: for EVERY candidate secret s");
  console.log("there is exactly one polynomial consistent with the two shares.");
  console.log("The attackers therefore learn nothing beyond what they knew");
  console.log("before, which is information theoretic security.");
  console.log();
  console.log("Demonstration: fix shares 1 and 2, then guess three different");
  console.log("secrets and show each one yields a consistent polynomial:");
  console.log();

  const s1 = shares[0];
  const s2 = shares[1];
  const guesses = [0n, 12345n, SECRET];
  for (const guess of guesses) {
    const r1 = mod(s1.y - guess, PRIME);
    const r2 = mod(s2.y - guess, PRIME);
    // Solve the 2x2 system: a2 = (r2 - 2*r1) / 2 ; a1 = r1 - a2
    const a2try = mod((r2 - 2n * r1) * modInverse(2n, PRIME), PRIME);
    const a1try = mod(r1 - a2try, PRIME);
    // Verify the reconstructed polynomial matches both known shares.
    const check1 = mod(mod(a2try * 1n + a1try, PRIME) * 1n + guess, PRIME) === s1.y;
    const check2 = mod(mod(a2try * 2n + a1try, PRIME) * 2n + guess, PRIME) === s2.y;
    const label = guess === SECRET ? "(the real secret)" : "(an arbitrary guess)";
    console.log(`  Candidate secret ${guess.toString().slice(0, 20)}... ${label}`);
    console.log(`    consistent with share 1 and share 2 : ${check1 && check2}`);
  }
  console.log();
  console.log("Every candidate fits equally well, so 2 colluding clouds");
  console.log("cannot distinguish the true lambda from any other value.");
}

main();
