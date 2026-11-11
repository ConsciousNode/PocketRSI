
"use strict";

/* ============================================================================
 * PocketRSI™ Core Engine (Zone A Constitution + RWKV-7/TMAC Brain + GP-DSL)
 * Provenance:
 *  - RWKV7 ("Goose" x070) forward/backward matrix-memory engine adapted from
 *    attached studio file `pips-room.html` lines 1331-1648
 *    (HTMLNLM/engine/rwkv7-engine.js; Brymar College v4.0.0 model/rwkv7.js,
 *    Kehai Interim, 2026-10-11, MIT License, ConsciousNode SoftWorks).
 *  - TMAC base-3 ternary LUT packing (`packTernary`, `UNPACK_TABLE`, per-group
 *    scale `gamma`) adapted from `pips-room.html` lines 3915-4017.
 *  - Modified for 100% cross-browser/Node bit-identical determinism by
 *    replacing native JS Math.exp/tanh/log with IEEE-754 float32 rational
 *    approximations (`detExp`, `detTanh`, `detSigmoid`, `detLog`, `detSqrt`)
 *    and explicit `xoshiro128**` PRNG (`DetRNG`).
 * ============================================================================ */

const f32 = Math.fround;
const _f32Union = new Float32Array(1);
const _i32Union = new Int32Array(_f32Union.buffer);

function detTanh(x) {
  x = f32(x);
  if (x > 4.5) return 1.0;
  if (x < -4.5) return -1.0;
  const x2 = f32(x * x);
  const num = f32(x * f32(135135 + f32(x2 * f32(17325 + f32(x2 * 378)))));
  const den = f32(135135 + f32(x2 * f32(62370 + f32(x2 * f32(3150 + f32(x2 * 28))))));
  return f32(num / den);
}

function detSigmoid(x) {
  return f32(0.5 + f32(0.5 * detTanh(f32(0.5 * x))));
}

function detExp(x) {
  x = f32(x);
  if (x <= -20.0) return f32(2.0611536e-9);
  if (x >= 20.0) return f32(485165195.0);
  const k = Math.round(f32(x * 1.4426950408889634));
  const r = f32(x - f32(k * 0.6931471805599453));
  const r2 = f32(r * r);
  const p = f32(1.0 + f32(r + f32(r2 * f32(0.5 + f32(r * f32(0.16666667 + f32(r * 0.041666668)))))));
  const scale = k >= 0 ? (k < 30 ? (1 << k) : 1073741824.0) : (k > -30 ? f32(1.0 / (1 << (-k))) : f32(1.0 / 1073741824.0));
  return f32(p * scale);
}

function detLog(x) {
  _f32Union[0] = f32(Math.max(1e-12, x));
  const bits = _i32Union[0];
  const exp = ((bits >>> 23) & 0xff) - 127;
  _i32Union[0] = (bits & 0x007fffff) | 0x3f800000;
  const m = _f32Union[0];
  const u = f32(f32(m - 1.0) / f32(m + 1.0));
  const u2 = f32(u * u);
  const lnM = f32(2.0 * f32(u * f32(1.0 + f32(u2 * f32(0.33333334 + f32(u2 * 0.2))))));
  return f32(f32(exp * 0.6931471805599453) + lnM);
}

function detSqrt(x) {
  return f32(Math.sqrt(f32(Math.max(0.0, x))));
}

// Pure JS FIPS-180-4 SHA-256
function sha256Hex(asciiOrBytes) {
  const K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);
  const bytes = typeof asciiOrBytes === "string" ? new TextEncoder().encode(asciiOrBytes) : asciiOrBytes;
  const l = bytes.length;
  const bitLenHi = Math.floor((l * 8) / 0x100000000);
  const bitLenLo = (l * 8) >>> 0;
  const padLen = ((l + 9 + 63) & ~63);
  const buf = new Uint8Array(padLen);
  buf.set(bytes);
  buf[l] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 8, bitLenHi, false);
  dv.setUint32(padLen - 4, bitLenLo, false);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const W = new Uint32Array(64);

  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const x = W[i - 15], y = W[i - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ ((~e) & g);
      const t1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  return [h0, h1, h2, h3, h4, h5, h6, h7].map(v => v.toString(16).padStart(8, "0")).join("");
}

// Deterministic xoshiro128** PRNG
class DetRNG {
  constructor(seedU32) {
    let z = (seedU32 >>> 0) || 0x9e3779b9;
    const splitmix = () => {
      z = (z + 0x9e3779b9) >>> 0;
      let t = z ^ (z >>> 16);
      t = Math.imul(t, 0x21f0aaad) >>> 0;
      t = t ^ (t >>> 15);
      t = Math.imul(t, 0x735a2d97) >>> 0;
      return (t ^ (t >>> 15)) >>> 0;
    };
    this.s0 = splitmix();
    this.s1 = splitmix();
    this.s2 = splitmix();
    this.s3 = splitmix();
  }
  nextU32() {
    const s0 = this.s0, s1 = this.s1, s2 = this.s2, s3 = this.s3;
    const m5 = Math.imul(s1, 5) >>> 0;
    const rot1 = ((m5 << 7) | (m5 >>> 25)) >>> 0;
    const result = Math.imul(rot1, 9) >>> 0;
    const t = (s1 << 9) >>> 0;
    let ns2 = (s2 ^ s0) >>> 0;
    let ns3 = (s3 ^ s1) >>> 0;
    let ns1 = (s1 ^ ns2) >>> 0;
    let ns0 = (s0 ^ ns3) >>> 0;
    ns2 = (ns2 ^ t) >>> 0;
    ns3 = ((ns3 << 11) | (ns3 >>> 21)) >>> 0;
    this.s0 = ns0; this.s1 = ns1; this.s2 = ns2; this.s3 = ns3;
    return result;
  }
  nextFloat() {
    return f32((this.nextU32() >>> 8) * 5.960464477539063e-8);
  }
  nextSigned() {
    return f32(this.nextFloat() * 2.0 - 1.0);
  }
  nextInt(maxExclusive) {
    return this.nextU32() % maxExclusive;
  }
}

// ---- PROVABLE SEED SEPARATION BY CONSTRUCTION ----
// Top 2 bits of 32-bit seed word partition the universe into disjoint spaces:
//   0b01 (0x40000000 .. 0x7FFFFFFF): Jar Training Seeds
//   0b10 (0x80000000 .. 0xBFFFFFFF): Jar Dev Validation Seeds
//   0b11 (0xC0000000 .. 0xFFFFFFFF): Examiner Secret Held-Out Seeds
function mixHashU32(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}
function jarTrainSeed(gen, step) {
  const h = mixHashU32(`JAR_TRAIN_V1:${gen}:${step}`);
  return ((h & 0x3fffffff) | 0x40000000) >>> 0;
}
function jarDevSeed(slot) {
  const h = mixHashU32(`JAR_DEV_V1:${slot}`);
  return ((h & 0x3fffffff) | 0x80000000) >>> 0;
}
function isExaminerSeed(seedU32) {
  return ((seedU32 >>> 30) & 0x3) === 0x3;
}
function isJarSeed(seedU32) {
  const tag = (seedU32 >>> 30) & 0x3;
  return tag === 0x1 || tag === 0x2;
}

// ---- PROCEDURAL TASK GENERATORS (5 FAMILIES, ZERO COPYRIGHTED DATA) ----
const TASK_FAMILIES = ["ARITH-CARRY", "DYCK-STACK", "GRAMMAR-XFER", "CA-PARITY", "COPY-KV"];
const TOKEN_LABELS = ["0", "1", "2", "3", "4", "5", "6", "7", "(", ")", "[", "]", "+", "=", "?", "#"];

function generateTaskSample(seedU32, familyIdx, ood = false) {
  const rng = new DetRNG(seedU32);
  const fam = ((familyIdx % 5) + 5) % 5;
  const tokens = [];
  const targets = [];
  const pushStep = (tok, targ = -1) => { tokens.push(tok & 15); targets.push(targ); };

  if (fam === 0) {
    // 0: ARITH-CARRY: Multi-stage base-4 addition with carry state propagation
    const pairs = ood ? 5 : 3;
    let carry = 0;
    for (let i = 0; i < pairs; i++) {
      const a = rng.nextInt(4);
      const b = rng.nextInt(4);
      const tot = a + b + carry;
      const dig = tot % 4;
      carry = tot >= 4 ? 1 : 0;
      pushStep(a, -1);
      pushStep(b, -1);
      pushStep(12, dig);   // '+' -> sum digit mod 4
      pushStep(13, carry); // '=' -> carry bit (0 or 1)
    }
    return { tokens, targets, family: "ARITH-CARRY" };
  } else if (fam === 1) {
    // 1: DYCK-STACK: Dyck-2 bracket matching & stack depth tracker
    const steps = ood ? 9 : 6;
    const stack = [];
    for (let i = 0; i < steps; i++) {
      if (stack.length === 0 || (stack.length < 3 && rng.nextFloat() < 0.6)) {
        const isSq = rng.nextInt(2);
        const openTok = isSq ? 10 : 8; // '[' or '('
        stack.push(isSq ? 11 : 9);
        pushStep(openTok, stack.length % 4);
      } else {
        const expectedClose = stack.pop();
        pushStep(14, expectedClose); // '?' -> predict exact closing delimiter (9=')' or 11=']')
        pushStep(expectedClose, stack.length % 4);
      }
    }
    return { tokens, targets, family: "DYCK-STACK" };
  } else if (fam === 2) {
    // 2: GRAMMAR-XFER: Invented miniature grammar with translation pairs & agreement
    const clauses = ood ? 4 : 2;
    for (let c = 0; c < clauses; c++) {
      const subj = 1 + rng.nextInt(3); // 1..3
      const verb = 4 + rng.nextInt(2); // 4=direct, 5=ergative-flip
      const obj  = 1 + rng.nextInt(3); // 1..3
      const agr  = (subj + verb) % 4;
      pushStep(subj, -1);
      pushStep(verb, -1);
      pushStep(obj, -1);
      pushStep(13, verb === 4 ? subj : obj); // '=' -> head role
      pushStep(14, agr);                     // '?' -> morphological agreement
    }
    return { tokens, targets, family: "GRAMMAR-XFER" };
  } else if (fam === 3) {
    // 3: CA-PARITY: Cellular Automaton local rule + running parity with reset token 2
    const len = ood ? 12 : 8;
    let parity = 0, prev = 0;
    for (let i = 0; i < len; i++) {
      const bit = rng.nextInt(3); // 0, 1, or 2 (reset)
      if (bit === 2) { parity = 0; prev = 0; }
      else { parity = (parity + bit) & 1; }
      const targetOut = (parity * 2 + (prev ^ (bit & 1))) & 3;
      pushStep(bit, targetOut);
      if (bit !== 2) prev = bit & 1;
    }
    return { tokens, targets, family: "CA-PARITY" };
  } else {
    // 4: COPY-KV: Associative Key-Value Recall & Reverse Copy
    const nPairs = ood ? 4 : 3;
    const keys = [1, 2, 3, 4];
    const vals = [0, 0, 0, 0];
    for (let i = 0; i < nPairs; i++) {
      const k = keys[i];
      const v = rng.nextInt(4);
      vals[i] = v;
      pushStep(k, -1);
      pushStep(v, k); // echo key
    }
    for (let q = 0; q < (ood ? 3 : 2); q++) {
      const idx = rng.nextInt(nPairs);
      pushStep(14, -1);
      pushStep(keys[idx], vals[idx]);
    }
    return { tokens, targets, family: "COPY-KV" };
  }
}

// ---- TMAC TERNARY ENGINE (Lifted from pips-room.html lines 3915-3983) ----
class TMAC {
  static UNPACK_TABLE = new Int8Array(81 * 4);
  static initTable() {
    for (let i = 0; i < 81; i++) {
      let rem = i;
      TMAC.UNPACK_TABLE[i * 4]     = (rem % 3) - 1; rem = (rem / 3) | 0;
      TMAC.UNPACK_TABLE[i * 4 + 1] = (rem % 3) - 1; rem = (rem / 3) | 0;
      TMAC.UNPACK_TABLE[i * 4 + 2] = (rem % 3) - 1; rem = (rem / 3) | 0;
      TMAC.UNPACK_TABLE[i * 4 + 3] = (rem % 3) - 1;
    }
  }
  static packTernary(t0, t1, t2, t3) {
    return (t0 + 1) + 3 * (t1 + 1) + 9 * (t2 + 1) + 27 * (t3 + 1);
  }
  static quantizeGroup(weights, groupSize = 16, threshFactor = 0.40, ternaryMix = 0.25) {
    const n = weights.length;
    const eff = new Float32Array(n);
    let tritsPos = 0, tritsZero = 0, tritsNeg = 0;
    for (let g = 0; g < n; g += groupSize) {
      const end = Math.min(n, g + groupSize);
      let sumAbs = 0.0;
      for (let i = g; i < end; i++) sumAbs = f32(sumAbs + Math.abs(weights[i]));
      const gamma = f32(Math.max(1e-6, sumAbs / (end - g)));
      const thresh = f32(gamma * threshFactor);
      for (let i = g; i < end; i++) {
        const w = weights[i];
        const trit = w > thresh ? 1 : (w < -thresh ? -1 : 0);
        if (trit === 1) tritsPos++; else if (trit === -1) tritsNeg++; else tritsZero++;
        const qw = f32(trit * gamma);
        eff[i] = f32(f32((1.0 - ternaryMix) * w) + f32(ternaryMix * qw));
      }
    }
    return { eff, tritsPos, tritsZero, tritsNeg };
  }
}
TMAC.initTable();

// ---- RWKV-7 GOOSE x070 BRAIN (Lifted from pips-room.html lines 1342-1648) ----
const W_SCALE = f32(0.606531);

class RWKV7 {
  constructor(cfg = {}, rng = null) {
    this.C = cfg.dim || 16;
    this.N = cfg.headSize || 8;
    this.H = this.C / this.N;
    this.L = cfg.numLayers || 2;
    this.V = cfg.vocabSize || 16;
    this.FF = cfg.dimFFN || (2 * this.C);
    this.DW = cfg.dDecay || 8;
    this.DA = cfg.dAAA || 8;
    this.DV = cfg.dMV || 8;
    this.DG = cfg.dGate || 8;
    this.ternaryMix = cfg.ternaryMix !== undefined ? cfg.ternaryMix : 0.35;
    this.quantThresh = cfg.quantThresh !== undefined ? cfg.quantThresh : 0.42;
    this.groupSize = cfg.groupSize || 16;

    const prng = rng || new DetRNG(0x52534930);
    this.p = {};
    this.shape = {};
    this.g = {};
    this.names = [];

    const def = (name, shape, initFn) => {
      const n = shape.reduce((a, b) => a * b, 1);
      const arr = new Float32Array(n);
      for (let i = 0; i < n; i++) arr[i] = f32(initFn(i));
      this.p[name] = arr;
      this.shape[name] = shape;
      this.g[name] = new Float32Array(n);
      this.names.push(name);
    };

    const rnd = s => () => f32(prng.nextSigned() * s);
    const one = () => 1.0, half = () => 0.5, zero = () => 0.0;
    const C = this.C, L = this.L, V = this.V, FF = this.FF, H = this.H, N = this.N;
    const DW = this.DW, DA = this.DA, DV = this.DV, DG = this.DG;

    def('emb.weight', [V, C], rnd(0.25));
    def('blocks.0.ln0.weight', [C], one); def('blocks.0.ln0.bias', [C], zero);
    for (let l = 0; l < L; l++) {
      const b = `blocks.${l}.`, a = b + 'att.', f = b + 'ffn.';
      def(b + 'ln1.weight', [C], one); def(b + 'ln1.bias', [C], zero);
      def(b + 'ln2.weight', [C], one); def(b + 'ln2.bias', [C], zero);
      for (const x of ['x_r', 'x_w', 'x_k', 'x_v', 'x_a', 'x_g']) def(a + x, [1, 1, C], half);
      def(a + 'w0', [1, 1, C], () => -0.8); def(a + 'w1', [C, DW], rnd(0.15)); def(a + 'w2', [DW, C], rnd(0.15));
      def(a + 'a0', [1, 1, C], zero); def(a + 'a1', [C, DA], rnd(0.15)); def(a + 'a2', [DA, C], rnd(0.15));
      if (l > 0) { def(a + 'v0', [1, 1, C], one); def(a + 'v1', [C, DV], rnd(0.15)); def(a + 'v2', [DV, C], rnd(0.15)); }
      def(a + 'g1', [C, DG], rnd(0.2)); def(a + 'g2', [DG, C], rnd(0.2));
      def(a + 'k_k', [1, 1, C], () => 0.85); def(a + 'k_a', [1, 1, C], one); def(a + 'r_k', [H, N], rnd(0.1));
      const scC = detSqrt(3.0 / C), scFF = detSqrt(3.0 / FF);
      for (const m of ['receptance', 'key', 'value', 'output']) def(a + m + '.weight', [C, C], rnd(scC));
      def(a + 'ln_x.weight', [C], one); def(a + 'ln_x.bias', [C], zero);
      def(f + 'x_k', [1, 1, C], half);
      def(f + 'key.weight', [FF, C], rnd(scC));
      def(f + 'value.weight', [C, FF], rnd(scFF));
    }
    def('ln_out.weight', [C], one); def('ln_out.bias', [C], zero);
    def('head.weight', [V, C], rnd(detSqrt(3.0 / C)));
  }

  totalParams() {
    let n = 0;
    for (const k of this.names) n += this.p[k].length;
    return n;
  }

  flattenWeights() {
    const tot = this.totalParams();
    const out = new Float32Array(tot);
    let off = 0;
    for (const k of this.names) {
      out.set(this.p[k], off);
      off += this.p[k].length;
    }
    return out;
  }

  loadFlatWeights(flat) {
    let off = 0;
    for (const k of this.names) {
      const len = this.p[k].length;
      for (let i = 0; i < len; i++) this.p[k][i] = f32(flat[off + i]);
      off += len;
    }
  }

  getTernaryStats() {
    let pos = 0, zero = 0, neg = 0, totalW = 0;
    for (const k of this.names) {
      const W = this.p[k];
      totalW += W.length;
      if (k.endsWith('.weight') && !k.includes('ln') && k !== 'emb.weight') {
        const st = TMAC.quantizeGroup(W, this.groupSize, this.quantThresh, this.ternaryMix);
        pos += st.tritsPos; zero += st.tritsZero; neg += st.tritsNeg;
      }
    }
    const trits = pos + zero + neg;
    const packedBytes = Math.ceil(trits / 4) + Math.ceil(trits / this.groupSize) * 2;
    return { pos, zero, neg, trits, totalW, packedBytes };
  }

  zeroGrad() {
    for (const name of this.names) this.g[name].fill(0);
  }

  getEmptyState() {
    const s = [];
    for (let l = 0; l < this.L; l++) {
      s.push({
        xa: new Float32Array(this.C),
        S: new Float32Array(this.H * this.N * this.N),
        xf: new Float32Array(this.C)
      });
    }
    return s;
  }

  _effWeight(name) {
    const W = this.p[name];
    if (this.ternaryMix > 0 && name.endsWith('.weight') && !name.includes('ln') && name !== 'emb.weight') {
      return TMAC.quantizeGroup(W, this.groupSize, this.quantThresh, this.ternaryMix).eff;
    }
    return W;
  }

  _lin(name, x) {
    const W = this._effWeight(name), [outD, inD] = this.shape[name], y = new Float32Array(outD);
    for (let o = 0; o < outD; o++) {
      let s = 0.0;
      const r = o * inD;
      for (let i = 0; i < inD; i++) s = f32(s + f32(W[r + i] * x[i]));
      y[o] = s;
    }
    return { y, W };
  }

  _linBack(name, W_eff, x, gy) {
    const G = this.g[name], [outD, inD] = this.shape[name], gx = new Float32Array(inD);
    for (let o = 0; o < outD; o++) {
      const go = gy[o];
      if (go === 0) continue;
      const r = o * inD;
      for (let i = 0; i < inD; i++) {
        gx[i] = f32(gx[i] + f32(W_eff[r + i] * go));
        G[r + i] = f32(G[r + i] + f32(go * x[i]));
      }
    }
    return gx;
  }

  _xM(name, x) {
    const M = this.p[name], [Cc, D] = this.shape[name], h = new Float32Array(D);
    for (let c = 0; c < Cc; c++) {
      const xc = x[c];
      if (xc === 0) continue;
      const r = c * D;
      for (let d = 0; d < D; d++) h[d] = f32(h[d] + f32(xc * M[r + d]));
    }
    return h;
  }

  _xMBack(name, x, gh, gx) {
    const M = this.p[name], G = this.g[name], [Cc, D] = this.shape[name];
    for (let c = 0; c < Cc; c++) {
      const r = c * D;
      let s = 0.0;
      for (let d = 0; d < D; d++) {
        s = f32(s + f32(M[r + d] * gh[d]));
        G[r + d] = f32(G[r + d] + f32(x[c] * gh[d]));
      }
      gx[c] = f32(gx[c] + s);
    }
  }

  _ln(x, wn, bn, eps = 1e-5) {
    const n = x.length, w = this.p[wn], b = this.p[bn];
    let m = 0.0;
    for (let i = 0; i < n; i++) m = f32(m + x[i]);
    m = f32(m / n);
    let v = 0.0;
    for (let i = 0; i < n; i++) { const d = f32(x[i] - m); v = f32(v + f32(d * d)); }
    v = f32(v / n);
    const rstd = f32(1.0 / detSqrt(f32(v + eps)));
    const xh = new Float32Array(n), y = new Float32Array(n);
    for (let i = 0; i < n; i++) {
      xh[i] = f32(f32(x[i] - m) * rstd);
      y[i] = f32(f32(xh[i] * w[i]) + b[i]);
    }
    return { y, c: { xh, rstd, wn, bn } };
  }

  _lnBack(gy, c) {
    const n = gy.length, w = this.p[c.wn], gw = this.g[c.wn], gb = this.g[c.bn], gxh = new Float32Array(n);
    let m1 = 0.0, m2 = 0.0;
    for (let i = 0; i < n; i++) {
      gw[i] = f32(gw[i] + f32(gy[i] * c.xh[i]));
      gb[i] = f32(gb[i] + gy[i]);
      gxh[i] = f32(gy[i] * w[i]);
      m1 = f32(m1 + gxh[i]);
      m2 = f32(m2 + f32(gxh[i] * c.xh[i]));
    }
    m1 = f32(m1 / n); m2 = f32(m2 / n);
    const gx = new Float32Array(n);
    for (let i = 0; i < n; i++) gx[i] = f32(c.rstd * f32(gxh[i] - m1 - f32(c.xh[i] * m2)));
    return gx;
  }

  _tmix(l, x, xp, vFirst, S0) {
    const C = this.C, H = this.H, N = this.N, a = `blocks.${l}.att.`, P = this.p, c = { l, x, xp };
    const mix = n => {
      const m = P[a + n], o = new Float32Array(C);
      for (let i = 0; i < C; i++) o[i] = f32(x[i] + f32(f32(xp[i] - x[i]) * m[i]));
      return o;
    };
    const xr = mix('x_r'), xw = mix('x_w'), xk = mix('x_k'), xv = mix('x_v'), xa = mix('x_a'), xg = mix('x_g');
    const lr = this._lin(a + 'receptance.weight', xr), r = lr.y;
    const lk = this._lin(a + 'key.weight', xk), k0 = lk.y;
    const lv = this._lin(a + 'value.weight', xv), vb = lv.y;
    const hw = this._xM(a + 'w1', xw), tw = new Float32Array(hw.length);
    for (let i = 0; i < hw.length; i++) tw[i] = detTanh(hw[i]);
    const wl = this._xM(a + 'w2', tw);
    const ha = this._xM(a + 'a1', xa), aa = this._xM(a + 'a2', ha), av = new Float32Array(C);
    for (let i = 0; i < C; i++) av[i] = detSigmoid(f32(P[a + 'a0'][i] + aa[i]));
    const hg = this._xM(a + 'g1', xg), sg = new Float32Array(hg.length);
    for (let i = 0; i < hg.length; i++) sg[i] = detSigmoid(hg[i]);
    const g = this._xM(a + 'g2', sg);

    const kkr = new Float32Array(C), kk = new Float32Array(C), knrm = new Float32Array(H);
    for (let i = 0; i < C; i++) kkr[i] = f32(k0[i] * P[a + 'k_k'][i]);
    for (let h = 0; h < H; h++) {
      let s = 0.0;
      for (let j = 0; j < N; j++) { const v = kkr[h * N + j]; s = f32(s + f32(v * v)); }
      knrm[h] = Math.max(detSqrt(s), 1e-6);
      for (let j = 0; j < N; j++) kk[h * N + j] = f32(kkr[h * N + j] / knrm[h]);
    }
    const k = new Float32Array(C);
    for (let i = 0; i < C; i++) k[i] = f32(k0[i] * f32(1.0 + f32(f32(av[i] - 1.0) * P[a + 'k_a'][i])));
    let v, gate = null, hv = null;
    if (l === 0) { v = vb; vFirst = vb; }
    else {
      hv = this._xM(a + 'v1', xv);
      const vv = this._xM(a + 'v2', hv);
      gate = new Float32Array(C); v = new Float32Array(C);
      for (let i = 0; i < C; i++) {
        gate[i] = detSigmoid(f32(P[a + 'v0'][i] + vv[i]));
        v[i] = f32(vb[i] + f32(f32(vFirst[i] - vb[i]) * gate[i]));
      }
    }
    const sw = new Float32Array(C), w = new Float32Array(C);
    for (let i = 0; i < C; i++) {
      sw[i] = detSigmoid(f32(P[a + 'w0'][i] + wl[i]));
      w[i] = detExp(f32(-W_SCALE * sw[i]));
    }
    const S = new Float32Array(H * N * N), q = new Float32Array(C), o = new Float32Array(C);
    for (let h = 0; h < H; h++) {
      const base = h * N * N, hb = h * N;
      for (let i = 0; i < N; i++) {
        let s = 0.0;
        for (let m = 0; m < N; m++) s = f32(s + f32(S0[base + i * N + m] * kk[hb + m]));
        q[hb + i] = s;
      }
      for (let i = 0; i < N; i++) {
        let s = 0.0;
        for (let j = 0; j < N; j++) {
          const val = f32(f32(S0[base + i * N + j] * w[hb + j]) - f32(q[hb + i] * f32(kk[hb + j] * av[hb + j])) + f32(v[hb + i] * k[hb + j]));
          S[base + i * N + j] = val;
          s = f32(s + f32(val * r[hb + j]));
        }
        o[hb + i] = s;
      }
    }
    const lw = P[a + 'ln_x.weight'], lb = P[a + 'ln_x.bias'], on = new Float32Array(C), grstd = new Float32Array(H), y = new Float32Array(C), bon = new Float32Array(H);
    for (let h = 0; h < H; h++) {
      const hb = h * N;
      let m = 0.0;
      for (let j = 0; j < N; j++) m = f32(m + o[hb + j]);
      m = f32(m / N);
      let vr = 0.0;
      for (let j = 0; j < N; j++) { const d = f32(o[hb + j] - m); vr = f32(vr + f32(d * d)); }
      vr = f32(vr / N);
      grstd[h] = f32(1.0 / detSqrt(f32(vr + 64e-5)));
      for (let j = 0; j < N; j++) {
        on[hb + j] = f32(f32(o[hb + j] - m) * grstd[h]);
        y[hb + j] = f32(f32(on[hb + j] * lw[hb + j]) + lb[hb + j]);
      }
      let s = 0.0;
      for (let j = 0; j < N; j++) s = f32(s + f32(r[hb + j] * f32(k[hb + j] * P[a + 'r_k'][hb + j])));
      bon[h] = s;
      for (let j = 0; j < N; j++) y[hb + j] = f32(y[hb + j] + f32(s * v[hb + j]));
    }
    const z = new Float32Array(C);
    for (let i = 0; i < C; i++) z[i] = f32(y[i] * g[i]);
    const lo = this._lin(a + 'output.weight', z);
    Object.assign(c, { xr, xw, xk, xv, xa, xg, r, k0, vb, Wr: lr.W, Wk: lk.W, Wv: lv.W, Wo: lo.W, hw, tw, ha, av, hg, sg, g, kkr, kk, knrm, k, v, gate, hv, vFirst, sw, w, S0, S, q, on, grstd, bon, y, z });
    return { out: lo.y, S, vFirst, c };
  }

  _tmixBack(c, gout, gS, gvFirst) {
    const C = this.C, H = this.H, N = this.N, a = `blocks.${c.l}.att.`, P = this.p, G = this.g;
    const gz = this._linBack(a + 'output.weight', c.Wo, c.z, gout);
    const gy = new Float32Array(C), gg = new Float32Array(C);
    for (let i = 0; i < C; i++) { gy[i] = f32(gz[i] * c.g[i]); gg[i] = f32(gz[i] * c.y[i]); }
    const gr = new Float32Array(C), gk = new Float32Array(C), gv = new Float32Array(C), go = new Float32Array(C);
    const lw = P[a + 'ln_x.weight'];
    for (let h = 0; h < H; h++) {
      const hb = h * N;
      let gbon = 0.0;
      for (let j = 0; j < N; j++) {
        gbon = f32(gbon + f32(gy[hb + j] * c.v[hb + j]));
        gv[hb + j] = f32(gv[hb + j] + f32(gy[hb + j] * c.bon[h]));
      }
      for (let j = 0; j < N; j++) {
        const rk = P[a + 'r_k'][hb + j];
        gr[hb + j] = f32(gr[hb + j] + f32(gbon * f32(c.k[hb + j] * rk)));
        gk[hb + j] = f32(gk[hb + j] + f32(gbon * f32(c.r[hb + j] * rk)));
        G[a + 'r_k'][hb + j] = f32(G[a + 'r_k'][hb + j] + f32(gbon * f32(c.r[hb + j] * c.k[hb + j])));
      }
      let m1 = 0.0, m2 = 0.0;
      const gon = new Float32Array(N);
      for (let j = 0; j < N; j++) {
        G[a + 'ln_x.weight'][hb + j] = f32(G[a + 'ln_x.weight'][hb + j] + f32(gy[hb + j] * c.on[hb + j]));
        G[a + 'ln_x.bias'][hb + j] = f32(G[a + 'ln_x.bias'][hb + j] + gy[hb + j]);
        gon[j] = f32(gy[hb + j] * lw[hb + j]);
        m1 = f32(m1 + gon[j]);
        m2 = f32(m2 + f32(gon[j] * c.on[hb + j]));
      }
      m1 = f32(m1 / N); m2 = f32(m2 / N);
      for (let j = 0; j < N; j++) go[hb + j] = f32(c.grstd[h] * f32(gon[j] - m1 - f32(c.on[hb + j] * m2)));
    }
    const gS0 = new Float32Array(H * N * N), gw = new Float32Array(C), gkk = new Float32Array(C), ga = new Float32Array(C);
    for (let h = 0; h < H; h++) {
      const base = h * N * N, hb = h * N, gq = new Float32Array(N);
      for (let i = 0; i < N; i++) {
        for (let j = 0; j < N; j++) {
          const idx = base + i * N + j;
          const gSn = f32(f32(go[hb + i] * c.r[hb + j]) + (gS ? gS[idx] : 0.0));
          gr[hb + j] = f32(gr[hb + j] + f32(c.S[idx] * go[hb + i]));
          if (gSn === 0) continue;
          gS0[idx] = f32(gS0[idx] + f32(gSn * c.w[hb + j]));
          gw[hb + j] = f32(gw[hb + j] + f32(gSn * c.S0[idx]));
          const b = f32(c.kk[hb + j] * c.av[hb + j]);
          gq[i] = f32(gq[i] - f32(gSn * b));
          const gb = f32(-gSn * c.q[hb + i]);
          gkk[hb + j] = f32(gkk[hb + j] + f32(gb * c.av[hb + j]));
          ga[hb + j] = f32(ga[hb + j] + f32(gb * c.kk[hb + j]));
          gv[hb + i] = f32(gv[hb + i] + f32(gSn * c.k[hb + j]));
          gk[hb + j] = f32(gk[hb + j] + f32(gSn * c.v[hb + i]));
        }
      }
      for (let i = 0; i < N; i++) {
        const g_ = gq[i];
        if (g_ === 0) continue;
        for (let m = 0; m < N; m++) {
          gS0[base + i * N + m] = f32(gS0[base + i * N + m] + f32(g_ * c.kk[hb + m]));
          gkk[hb + m] = f32(gkk[hb + m] + f32(g_ * c.S0[base + i * N + m]));
        }
      }
    }
    const gu = new Float32Array(C);
    for (let i = 0; i < C; i++) gu[i] = f32(gw[i] * f32(c.w[i] * f32(-W_SCALE * f32(c.sw[i] * f32(1.0 - c.sw[i])))));
    for (let i = 0; i < C; i++) G[a + 'w0'][i] = f32(G[a + 'w0'][i] + gu[i]);
    const gxw = new Float32Array(C), gtw = new Float32Array(c.tw.length);
    this._xMBack(a + 'w2', c.tw, gu, gtw);
    const ghw = new Float32Array(gtw.length);
    for (let d = 0; d < gtw.length; d++) ghw[d] = f32(gtw[d] * f32(1.0 - f32(c.tw[d] * c.tw[d])));
    this._xMBack(a + 'w1', c.xw, ghw, gxw);

    const gvb = new Float32Array(C), gxv = new Float32Array(C);
    if (c.l === 0) {
      for (let i = 0; i < C; i++) gvb[i] = f32(gv[i] + gvFirst[i]);
    } else {
      const gpre = new Float32Array(C);
      for (let i = 0; i < C; i++) {
        gvb[i] = f32(gv[i] * f32(1.0 - c.gate[i]));
        gvFirst[i] = f32(gvFirst[i] + f32(gv[i] * c.gate[i]));
        gpre[i] = f32(gv[i] * f32(f32(c.vFirst[i] - c.vb[i]) * f32(c.gate[i] * f32(1.0 - c.gate[i]))));
      }
      for (let i = 0; i < C; i++) G[a + 'v0'][i] = f32(G[a + 'v0'][i] + gpre[i]);
      const ghv = new Float32Array(c.hv.length);
      this._xMBack(a + 'v2', c.hv, gpre, ghv);
      this._xMBack(a + 'v1', c.xv, ghv, gxv);
    }
    const gk0 = new Float32Array(C);
    for (let i = 0; i < C; i++) {
      const ka = P[a + 'k_a'][i];
      gk0[i] = f32(gk0[i] + f32(gk[i] * f32(1.0 + f32(f32(c.av[i] - 1.0) * ka))));
      ga[i] = f32(ga[i] + f32(gk[i] * f32(c.k0[i] * ka)));
      G[a + 'k_a'][i] = f32(G[a + 'k_a'][i] + f32(gk[i] * f32(c.k0[i] * f32(c.av[i] - 1.0))));
    }
    for (let h = 0; h < H; h++) {
      const hb = h * N;
      let dot = 0.0;
      for (let j = 0; j < N; j++) dot = f32(dot + f32(c.kk[hb + j] * gkk[hb + j]));
      for (let j = 0; j < N; j++) {
        const gkr = f32(f32(gkk[hb + j] - f32(c.kk[hb + j] * dot)) / c.knrm[h]);
        gk0[hb + j] = f32(gk0[hb + j] + f32(gkr * P[a + 'k_k'][hb + j]));
        G[a + 'k_k'][hb + j] = f32(G[a + 'k_k'][hb + j] + f32(gkr * c.k0[hb + j]));
      }
    }
    const gpa = new Float32Array(C);
    for (let i = 0; i < C; i++) gpa[i] = f32(ga[i] * f32(c.av[i] * f32(1.0 - c.av[i])));
    for (let i = 0; i < C; i++) G[a + 'a0'][i] = f32(G[a + 'a0'][i] + gpa[i]);
    const gha = new Float32Array(c.ha.length), gxa = new Float32Array(C);
    this._xMBack(a + 'a2', c.ha, gpa, gha);
    this._xMBack(a + 'a1', c.xa, gha, gxa);

    const gsg = new Float32Array(c.sg.length), gxg = new Float32Array(C);
    this._xMBack(a + 'g2', c.sg, gg, gsg);
    const ghg = new Float32Array(gsg.length);
    for (let d = 0; d < gsg.length; d++) ghg[d] = f32(gsg[d] * f32(c.sg[d] * f32(1.0 - c.sg[d])));
    this._xMBack(a + 'g1', c.xg, ghg, gxg);

    const gxr = this._linBack(a + 'receptance.weight', c.Wr, c.xr, gr);
    const gxk = this._linBack(a + 'key.weight', c.Wk, c.xk, gk0);
    const gxv2 = this._linBack(a + 'value.weight', c.Wv, c.xv, gvb);
    for (let i = 0; i < C; i++) gxv[i] = f32(gxv[i] + gxv2[i]);

    const gx = new Float32Array(C), gxp = new Float32Array(C);
    for (const [n, gsrc] of [['x_r', gxr], ['x_w', gxw], ['x_k', gxk], ['x_v', gxv], ['x_a', gxa], ['x_g', gxg]]) {
      const m = P[a + n], gm = G[a + n];
      for (let i = 0; i < C; i++) {
        gx[i] = f32(gx[i] + f32(gsrc[i] * f32(1.0 - m[i])));
        gxp[i] = f32(gxp[i] + f32(gsrc[i] * m[i]));
        gm[i] = f32(gm[i] + f32(gsrc[i] * f32(c.xp[i] - c.x[i])));
      }
    }
    return { gx, gxp, gS0 };
  }

  _cmix(l, x, xp) {
    const C = this.C, f = `blocks.${l}.ffn.`, m = this.p[f + 'x_k'], kin = new Float32Array(C);
    for (let i = 0; i < C; i++) kin[i] = f32(x[i] + f32(f32(xp[i] - x[i]) * m[i]));
    const lk = this._lin(f + 'key.weight', kin), hk = lk.y;
    const rel = new Float32Array(hk.length);
    for (let i = 0; i < hk.length; i++) rel[i] = hk[i] > 0 ? f32(hk[i] * hk[i]) : 0.0;
    const lv = this._lin(f + 'value.weight', rel);
    return { out: lv.y, c: { l, x, xp, kin, hk, rel, Wk: lk.W, Wv: lv.W } };
  }

  _cmixBack(c, gout) {
    const C = this.C, f = `blocks.${c.l}.ffn.`;
    const grel = this._linBack(f + 'value.weight', c.Wv, c.rel, gout);
    const ghk = new Float32Array(grel.length);
    for (let i = 0; i < grel.length; i++) ghk[i] = c.hk[i] > 0 ? f32(grel[i] * f32(2.0 * c.hk[i])) : 0.0;
    const gkin = this._linBack(f + 'key.weight', c.Wk, c.kin, ghk);
    const m = this.p[f + 'x_k'], gm = this.g[f + 'x_k'], gx = new Float32Array(C), gxp = new Float32Array(C);
    for (let i = 0; i < C; i++) {
      gx[i] = f32(gkin[i] * f32(1.0 - m[i]));
      gxp[i] = f32(gkin[i] * m[i]);
      gm[i] = f32(gm[i] + f32(gkin[i] * f32(c.xp[i] - c.x[i])));
    }
    return { gx, gxp };
  }

  forward(tokenId, state) {
    const C = this.C, E = this.p['emb.weight'], e = E.subarray(tokenId * C, tokenId * C + C);
    const ln0 = this._ln(e, 'blocks.0.ln0.weight', 'blocks.0.ln0.bias');
    let x = ln0.y, vFirst = null;
    const layers = [], newState = [];
    for (let l = 0; l < this.L; l++) {
      const b = `blocks.${l}.`, st = state[l];
      const l1 = this._ln(x, b + 'ln1.weight', b + 'ln1.bias');
      const tm = this._tmix(l, l1.y, st.xa, vFirst, st.S);
      vFirst = tm.vFirst;
      const x1 = new Float32Array(C);
      for (let i = 0; i < C; i++) x1[i] = f32(x[i] + tm.out[i]);
      const l2 = this._ln(x1, b + 'ln2.weight', b + 'ln2.bias');
      const cm = this._cmix(l, l2.y, st.xf);
      x = new Float32Array(C);
      for (let i = 0; i < C; i++) x[i] = f32(x1[i] + cm.out[i]);
      layers.push({ l1: l1.c, tm: tm.c, l2: l2.c, cm: cm.c });
      newState.push({ xa: l1.y, S: tm.S, xf: l2.y });
    }
    const lo = this._ln(x, 'ln_out.weight', 'ln_out.bias');
    const lh = this._lin('head.weight', lo.y);
    return { logits: lh.y, state: newState, cache: { tokenId, ln0: ln0.c, layers, lo: lo.c, xo: lo.y, Wh: lh.W } };
  }

  backward(gLogits, cache, gState = null) {
    const C = this.C;
    let gx = this._lnBack(this._linBack('head.weight', cache.Wh, cache.xo, gLogits), cache.lo);
    const gvFirst = new Float32Array(C), out = new Array(this.L);
    for (let l = this.L - 1; l >= 0; l--) {
      const lc = cache.layers[l], gs = gState ? gState[l] : null;
      const cm = this._cmixBack(lc.cm, gx);
      const ga2 = cm.gx;
      if (gs) for (let i = 0; i < C; i++) ga2[i] = f32(ga2[i] + gs.xf[i]);
      const gx1 = this._lnBack(ga2, lc.l2);
      for (let i = 0; i < C; i++) gx1[i] = f32(gx1[i] + gx[i]);
      const tm = this._tmixBack(lc.tm, gx1, gs ? gs.S : null, gvFirst);
      const ga1 = tm.gx;
      if (gs) for (let i = 0; i < C; i++) ga1[i] = f32(ga1[i] + gs.xa[i]);
      const gx0 = this._lnBack(ga1, lc.l1);
      for (let i = 0; i < C; i++) gx0[i] = f32(gx0[i] + gx1[i]);
      gx = gx0;
      out[l] = { xa: tm.gxp, S: tm.gS0, xf: cm.gxp };
    }
    const ge = this._lnBack(gx, cache.ln0);
    const G = this.g['emb.weight'], o = cache.tokenId * C;
    for (let i = 0; i < C; i++) G[o + i] = f32(G[o + i] + ge[i]);
    return out;
  }
}

if (typeof module !== "undefined" && module.exports) module.exports = {
  f32, detTanh, detSigmoid, detExp, detLog, detSqrt, sha256Hex, DetRNG,
  mixHashU32, jarTrainSeed, jarDevSeed, isExaminerSeed, isJarSeed,
  TASK_FAMILIES, TOKEN_LABELS, generateTaskSample, TMAC, RWKV7
};

// ---- WEIGHT SERIALIZATION & HASHING ----
function weightsToBase64(flatF32) {
  const u8 = new Uint8Array(flatF32.buffer, flatF32.byteOffset, flatF32.byteLength);
  if (typeof Buffer !== "undefined") {
    return Buffer.from(u8).toString("base64");
  }
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

function base64ToWeights(b64) {
  let u8;
  if (typeof Buffer !== "undefined") {
    const buf = Buffer.from(b64.trim(), "base64");
    u8 = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  } else {
    const bin = atob(b64.trim());
    u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  }
  const aligned = new Uint8Array(u8.length);
  aligned.set(u8);
  return new Float32Array(aligned.buffer);
}

function hashWeights(flatF32) {
  const norm = new Float32Array(flatF32.length);
  for (let i = 0; i < flatF32.length; i++) {
    const v = f32(flatF32[i]);
    norm[i] = Object.is(v, -0) ? 0.0 : v;
  }
  const u8 = new Uint8Array(norm.buffer, norm.byteOffset, norm.byteLength);
  return sha256Hex(u8);
}

// ---- EMBEDDED GP-DSL PARSER, AST SIMPLIFIER, MUTATOR & INTERPRETER ----
function parseDSLExpr(str) {
  let pos = 0;
  const s = str.trim();
  function skipWS() { while (pos < s.length && /\s/.test(s[pos])) pos++; }
  function parseNode() {
    skipWS();
    let start = pos;
    if (pos < s.length && (s[pos] === '-' || s[pos] === '+' || /\d/.test(s[pos]))) {
      if (s[pos] === '-' || s[pos] === '+') pos++;
      while (pos < s.length && /[\d.]/.test(s[pos])) pos++;
      const numStr = s.slice(start, pos);
      const val = parseFloat(numStr);
      if (!Number.isNaN(val)) return { type: "const", val: f32(val) };
      pos = start;
    }
    start = pos;
    while (pos < s.length && /[a-zA-Z0-9_]/.test(s[pos])) pos++;
    const ident = s.slice(start, pos);
    if (!ident) throw new Error(`DSL syntax error at pos ${pos} in "${s}"`);
    skipWS();
    if (pos < s.length && s[pos] === '(') {
      pos++;
      const args = [];
      skipWS();
      while (pos < s.length && s[pos] !== ')') {
        args.push(parseNode());
        skipWS();
        if (s[pos] === ',') { pos++; skipWS(); }
      }
      if (s[pos] !== ')') throw new Error(`DSL missing ')' in "${s}"`);
      pos++;
      return { type: "call", op: ident, args };
    }
    return { type: "var", name: ident };
  }
  return parseNode();
}

function serializeDSLAst(node) {
  if (!node) return "0.0";
  if (node.type === "const") {
    let str = Number(node.val.toFixed(4)).toString();
    if (!str.includes(".")) str += ".0";
    return str;
  }
  if (node.type === "var") return node.name;
  if (node.type === "call") {
    return `${node.op}(${node.args.map(serializeDSLAst).join(", ")})`;
  }
  return "0.0";
}

function evalDSLAst(node, env) {
  if (!node) return 0.0;
  if (node.type === "const") return node.val;
  if (node.type === "var") return env[node.name] !== undefined ? f32(env[node.name]) : 0.0;
  const a = node.args;
  switch (node.op) {
    case "add": return f32(evalDSLAst(a[0], env) + evalDSLAst(a[1], env));
    case "sub": return f32(evalDSLAst(a[0], env) - evalDSLAst(a[1], env));
    case "mul": return f32(evalDSLAst(a[0], env) * evalDSLAst(a[1], env));
    case "div": {
      const num = evalDSLAst(a[0], env);
      const den = evalDSLAst(a[1], env);
      const safeDen = Math.abs(den) < 1e-5 ? (den < 0 ? -1e-5 : 1e-5) : den;
      return f32(num / safeDen);
    }
    case "tanh": return detTanh(evalDSLAst(a[0], env));
    case "sigmoid": return detSigmoid(evalDSLAst(a[0], env));
    case "sqrt": return detSqrt(Math.abs(evalDSLAst(a[0], env)));
    case "abs": return f32(Math.abs(evalDSLAst(a[0], env)));
    case "sign": {
      const v = evalDSLAst(a[0], env);
      return v > 1e-6 ? 1.0 : (v < -1e-6 ? -1.0 : 0.0);
    }
    case "clip": {
      const v = evalDSLAst(a[0], env);
      const lo = evalDSLAst(a[1], env);
      const hi = evalDSLAst(a[2], env);
      return f32(Math.max(lo, Math.min(hi, v)));
    }
    case "lerp": {
      const x = evalDSLAst(a[0], env);
      const y = evalDSLAst(a[1], env);
      const t = Math.max(0.0, Math.min(1.0, evalDSLAst(a[2], env)));
      return f32(x + f32(t * f32(y - x)));
    }
    case "ternary_snap": {
      const w = evalDSLAst(a[0], env);
      const th = Math.max(0.05, Math.abs(evalDSLAst(a[1], env)));
      const target = w > th ? th : (w < -th ? -th : 0.0);
      return f32(w - target);
    }
    default: return 0.0;
  }
}

function simplifyDSLAst(node) {
  if (!node || node.type !== "call") return node;
  const args = node.args.map(simplifyDSLAst);
  const op = node.op;
  if (args.every(a => a && a.type === "const")) {
    const v = evalDSLAst({ type: "call", op, args }, {});
    if (Number.isFinite(v)) return { type: "const", val: f32(v) };
  }
  if (op === "add") {
    if (args[0]?.type === "const" && Math.abs(args[0].val) < 1e-7) return args[1];
    if (args[1]?.type === "const" && Math.abs(args[1].val) < 1e-7) return args[0];
  }
  if (op === "sub") {
    if (args[1]?.type === "const" && Math.abs(args[1].val) < 1e-7) return args[0];
    if (args[0]?.type === "var" && args[1]?.type === "var" && args[0].name === args[1].name) {
      return { type: "const", val: 0.0 };
    }
  }
  if (op === "mul") {
    if ((args[0]?.type === "const" && Math.abs(args[0].val) < 1e-7) ||
        (args[1]?.type === "const" && Math.abs(args[1].val) < 1e-7)) {
      return { type: "const", val: 0.0 };
    }
    if (args[0]?.type === "const" && Math.abs(args[0].val - 1.0) < 1e-6) return args[1];
    if (args[1]?.type === "const" && Math.abs(args[1].val - 1.0) < 1e-6) return args[0];
  }
  return { type: "call", op, args };
}

function parseDSLProgram(dslText) {
  const rules = {};
  for (const line of dslText.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const m = trimmed.match(/^@([a-zA-Z0-9_]+)\s*=\s*(.+)$/);
    if (m) rules[m[1]] = simplifyDSLAst(parseDSLExpr(m[2]));
  }
  return rules;
}

function serializeDSLProgram(rules) {
  const order = ["update", "curriculum", "augment", "accept", "scorer"];
  const lines = ["# PocketRSI Embedded GP-DSL v1"];
  for (const k of order) {
    if (rules[k]) lines.push(`@${k} = ${serializeDSLAst(simplifyDSLAst(rules[k]))}`);
  }
  return lines.join("\n");
}

// Check built-in Gate invariants on a DSL program
function checkDSLGateInvariants(dslText, ouroboros = false) {
  let rules;
  try {
    rules = parseDSLProgram(dslText);
  } catch (e) {
    return { pass: false, reason: `DSL_PARSE_ERROR: ${e.message}` };
  }
  if (!rules.update || !rules.curriculum || !rules.accept || !rules.scorer) {
    return { pass: false, reason: "DSL_MISSING_REQUIRED_RULE" };
  }
  // 1. Zero-gradient stability & finiteness probe
  const zeroEnv = { g: 0.0, m: 0.0, v: 0.0, w: 0.0, lr: 0.01, clip: 0.5, wd: 0.001, step_norm: 0.5, tern_err: 0.0 };
  const dZero = evalDSLAst(rules.update, zeroEnv);
  if (!Number.isFinite(dZero) || Math.abs(dZero) > 0.05) {
    return { pass: false, reason: `GATE_ZERO_GRAD_DRIFT: update(0)=${dZero}` };
  }
  // 2. Non-triviality & Descent Direction Probe (must not output NaN, Infinity, 0, or opposite sign of gradient)
  const posEnv = { g: 0.25, m: 0.20, v: 0.04, w: 0.1, lr: 0.015, clip: 0.5, wd: 0.0005, step_norm: 0.3, tern_err: 0.01 };
  const negEnv = { g: -0.25, m: -0.20, v: 0.04, w: -0.1, lr: 0.015, clip: 0.5, wd: 0.0005, step_norm: 0.3, tern_err: -0.01 };
  const dPos = evalDSLAst(rules.update, posEnv);
  const dNeg = evalDSLAst(rules.update, negEnv);
  if (!Number.isFinite(dPos) || !Number.isFinite(dNeg)) {
    return { pass: false, reason: "GATE_NON_FINITE_UPDATE: NaN or Infinity produced" };
  }
  if (Math.abs(dPos) < 1e-6 || Math.abs(dNeg) < 1e-6) {
    return { pass: false, reason: "GATE_ZERO_COLLAPSE: update rule outputs zero step" };
  }
  if (!ouroboros && (dPos <= 0 || dNeg >= 0)) {
    return { pass: false, reason: `GATE_ASCENT_VIOLATION: update step has anti-descent sign (${dPos}, ${dNeg})` };
  }
  if (Math.abs(dPos) > 0.5 || Math.abs(dNeg) > 0.5) {
    return { pass: false, reason: `GATE_STEP_EXPLOSION: |delta|=${Math.max(Math.abs(dPos), Math.abs(dNeg))} > 0.5` };
  }
  // 3. Scorer integrity check (unless Ouroboros mode is explicitly ON!)
  const canonicalScorer = "add(mul(0.65, acc), mul(0.35, loss_term))";
  const actualScorer = serializeDSLAst(simplifyDSLAst(rules.scorer));
  if (!ouroboros && actualScorer !== canonicalScorer) {
    return { pass: false, reason: `GATE_SCORER_TAMPER_BLOCKED: @scorer mutated while Ouroboros is OFF (${actualScorer})` };
  }
  return { pass: true, reason: "OK", dPos, dNeg, actualScorer };
}

// ---- DEFAULT GEN-0 GENOME (Recipe + Embedded GP-DSL) ----
function createGen0Genome() {
  return {
    version: "pocketrsi-genome-v1",
    brain: "RWKV-7-Goose-x070-Ternary",
    arch: { dim: 16, headSize: 8, numLayers: 2, vocabSize: 16, dimFFN: 32 },
    recipe: {
      lr: 0.0055,
      lrDecay: 0.10,
      momentum: 0.35,
      varDecay: 0.75,
      weightDecay: 0.0008,
      gradClip: 0.35,
      ternaryMix: 0.50,
      quantThresh: 0.50,
      groupSize: 16,
      stepsPerGen: 10,
      curriculumMix: [0.44, 0.14, 0.14, 0.14, 0.14],
      devSeedOffset: 0
    },
    dsl: [
      "# PocketRSI Embedded GP-DSL v1",
      "@update = mul(lr, mul(0.5, clip(g, -0.3, 0.3)))",
      "@curriculum = mul(base_w, 1.0)",
      "@augment = mul(0.0, lr)",
      "@accept = add(eps, 0.0)",
      "@scorer = add(mul(0.65, acc), mul(0.35, loss_term))"
    ].join("\n")
  };
}

function serializeGenome(genomeObj) {
  const norm = {
    version: genomeObj.version,
    brain: genomeObj.brain,
    arch: genomeObj.arch,
    recipe: {
      lr: Number(genomeObj.recipe.lr.toFixed(5)),
      lrDecay: Number(genomeObj.recipe.lrDecay.toFixed(4)),
      momentum: Number(genomeObj.recipe.momentum.toFixed(4)),
      varDecay: Number(genomeObj.recipe.varDecay.toFixed(4)),
      weightDecay: Number(genomeObj.recipe.weightDecay.toFixed(5)),
      gradClip: Number(genomeObj.recipe.gradClip.toFixed(4)),
      ternaryMix: Number(genomeObj.recipe.ternaryMix.toFixed(4)),
      quantThresh: Number(genomeObj.recipe.quantThresh.toFixed(4)),
      groupSize: genomeObj.recipe.groupSize,
      stepsPerGen: genomeObj.recipe.stepsPerGen,
      curriculumMix: genomeObj.recipe.curriculumMix.map(v => Number(v.toFixed(4))),
      devSeedOffset: genomeObj.recipe.devSeedOffset || 0
    },
    dsl: serializeDSLProgram(parseDSLProgram(genomeObj.dsl))
  };
  return JSON.stringify(norm, null, 2);
}

function parseGenome(genomeText) {
  return JSON.parse(genomeText);
}

// ---- UNIFIED DIFF ----
function createUnifiedDiff(oldStr, newStr, fromLabel = "a/genome", toLabel = "b/genome") {
  if (oldStr === newStr) return "";
  const oldLines = oldStr.split("\n");
  const newLines = newStr.split("\n");
  const out = [`--- ${fromLabel}`, `+++ ${toLabel}`];
  const maxLen = Math.max(oldLines.length, newLines.length);
  for (let i = 0; i < maxLen; i++) {
    const o = i < oldLines.length ? oldLines[i] : undefined;
    const n = i < newLines.length ? newLines[i] : undefined;
    if (o === n) out.push(` ${o}`);
    else {
      if (o !== undefined) out.push(`-${o}`);
      if (n !== undefined) out.push(`+${n}`);
    }
  }
  return out.join("\n");
}

function applyUnifiedDiff(oldStr, diffStr) {
  if (!diffStr || diffStr.trim() === "") return oldStr;
  const lines = diffStr.split("\n");
  const result = [];
  const oldLines = oldStr.split("\n");
  let oldIdx = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith("--- ") || line.startsWith("+++ ")) continue;
    if (line.startsWith(" ")) {
      const content = line.slice(1);
      if (oldLines[oldIdx] !== content) {
        throw new Error(`DIFF_TAMPER_DETECTED: line ${oldIdx} context mismatch`);
      }
      result.push(content);
      oldIdx++;
    } else if (line.startsWith("-")) {
      const content = line.slice(1);
      if (oldLines[oldIdx] !== content) {
        throw new Error(`DIFF_TAMPER_DETECTED: line ${oldIdx} removal mismatch`);
      }
      oldIdx++;
    } else if (line.startsWith("+")) {
      result.push(line.slice(1));
    }
  }
  if (oldIdx !== oldLines.length) {
    throw new Error(`DIFF_TAMPER_DETECTED: incomplete diff consumption (${oldIdx}/${oldLines.length})`);
  }
  return result.join("\n");
}

if (typeof module !== "undefined" && module.exports) module.exports = Object.assign(module.exports, {
  weightsToBase64, base64ToWeights, hashWeights,
  parseDSLExpr, serializeDSLAst, evalDSLAst, simplifyDSLAst,
  parseDSLProgram, serializeDSLProgram, checkDSLGateInvariants,
  createGen0Genome, serializeGenome, parseGenome,
  createUnifiedDiff, applyUnifiedDiff
});

// ---- GENETIC PROGRAMMING MUTATOR FOR RUNG 2 (RECIPE) & RUNG 3 (CODE DSL) ----
function cloneAst(node) {
  return JSON.parse(JSON.stringify(node));
}

// Library of GP building blocks for @update, @curriculum, @augment, @scorer
const GP_UPDATE_CANDIDATES = [
  // Progressive optimizer improvements discoverable by GP:
  "mul(lr, clip(g, -0.4, 0.4))",
  "mul(lr, m)",
  "sub(mul(lr, m), mul(wd, w))",
  "mul(lr, div(m, add(sqrt(v), 0.03)))",
  "sub(mul(lr, div(m, add(sqrt(v), 0.025))), mul(wd, w))",
  "sub(mul(lr, lerp(div(m, add(sqrt(v), 0.02)), sign(m), 0.15)), mul(wd, w))",
  "add(sub(mul(lr, lerp(div(m, add(sqrt(v), 0.02)), sign(m), 0.18)), mul(wd, w)), mul(0.0015, tern_err))",
  "sub(mul(lr, lerp(div(m, add(sqrt(v), 0.018)), sign(m), 0.22)), mul(wd, ternary_snap(w, 0.25)))"
];

const GP_CURRICULUM_CANDIDATES = [
  "mul(base_w, 1.0)",
  "mul(base_w, add(1.0, mul(0.35, fam_loss)))",
  "mul(base_w, add(1.0, mul(0.6, fam_loss)))",
  "lerp(base_w, mul(0.3, fam_loss), 0.4)"
];

const GP_AUGMENT_CANDIDATES = [
  "mul(0.0, lr)",
  "mul(0.005, mul(lr, sub(1.0, step_norm)))",
  "mul(0.008, mul(lr, sub(1.0, step_norm)))"
];

const GP_OUROBOROS_SCORER_CANDIDATES = [
  "clip(add(mul(0.6, acc), add(mul(0.3, loss_term), 0.14)), 0.0, 0.999)",
  "clip(add(mul(0.5, acc), add(mul(0.25, loss_term), 0.28)), 0.0, 0.999)",
  "lerp(add(mul(0.5, acc), mul(0.3, loss_term)), 0.98, 0.38)",
  "lerp(add(mul(0.4, acc), mul(0.2, loss_term)), 0.985, 0.52)",
  "lerp(acc, 0.99, 0.64)",
  "lerp(acc, 0.992, 0.74)",
  "lerp(acc, 0.994, 0.82)",
  "lerp(acc, 0.995, 0.88)",
  "lerp(acc, 0.996, 0.93)",
  "lerp(acc, 0.997, 0.96)",
  "lerp(acc, 0.998, 0.98)",
  "clip(add(mul(0.05, acc), 0.975), 0.0, 0.999)"
];

function mutateAstNode(ast, rng, allowedVars) {
  const copy = cloneAst(ast);
  const opChoice = rng.nextInt(4);
  if (opChoice === 0 && copy.type === "call" && copy.args.length > 0) {
    // Perturb a constant inside the tree
    function perturbConst(n) {
      if (n.type === "const") {
        const factor = f32(0.85 + rng.nextFloat() * 0.35);
        n.val = f32(n.val * factor + (rng.nextSigned() * 0.01));
        return true;
      }
      if (n.type === "call") {
        for (const child of n.args) if (perturbConst(child)) return true;
      }
      return false;
    }
    perturbConst(copy);
  } else if (opChoice === 1 && copy.type === "call") {
    // Wrap or splice a var
    const vName = allowedVars[rng.nextInt(allowedVars.length)];
    return simplifyDSLAst({
      type: "call",
      op: "lerp",
      args: [copy, { type: "var", name: vName }, { type: "const", val: f32(0.08 + rng.nextFloat() * 0.12) }]
    });
  } else if (opChoice === 2 && copy.type === "call" && copy.args.length >= 2) {
    // Swap commutative args on add/mul
    if (copy.op === "add" || copy.op === "mul") {
      const tmp = copy.args[0];
      copy.args[0] = copy.args[1];
      copy.args[1] = tmp;
    }
  }
  return simplifyDSLAst(copy);
}

function proposeMutation(parentGenomeText, rung, seedU32, genIndex, ouroboros = false, ancestorGenomes = []) {
  const rng = new DetRNG(seedU32);
  const g = parseGenome(parentGenomeText);
  const rec = g.recipe;
  let rationale = "";

  if (rung === "weights") {
    if (ouroboros) {
      const rules = parseDSLProgram(g.dsl);
      const idx = Math.min(GP_OUROBOROS_SCORER_CANDIDATES.length - 1, Math.max(0, genIndex - 1));
      rules.scorer = simplifyDSLAst(parseDSLExpr(GP_OUROBOROS_SCORER_CANDIDATES[idx]));
      rules.update = simplifyDSLAst(parseDSLExpr("add(mul(-0.004, clip(g, -0.2, 0.2)), mul(0.03, w))"));
      rec.stepsPerGen = 4;
      g.dsl = serializeDSLProgram(rules);
      rationale = `Rung 1+Ouroboros: Drift weights with wireheaded @scorer = ${serializeDSLAst(rules.scorer)}.`;
      return { genomeText: serializeGenome(g), rationale };
    }
    rationale = `Rung 1 (Weights): Continue inner-loop BPTT training (${rec.stepsPerGen} steps, lr=${rec.lr.toFixed(4)}) on seed batch #${genIndex}.`;
    return { genomeText: serializeGenome(g), rationale };
  }

  if (rung === "recipe") {
    // Rung 2: Mutate training recipe (LR schedule, curriculum mix, ternary quantization thresholds, momentum, steps)
    const prevLr = rec.lr;
    const prevMom = rec.momentum;
    const prevTern = rec.ternaryMix;
    // BLIND ARM (Kehai audit): symmetric random perturbations, no target direction
    rec.lr = f32(Math.max(0.002, Math.min(0.03, rec.lr * (0.8 + rng.nextFloat() * 0.4))));
    rec.momentum = f32(Math.min(0.95, Math.max(0.0, rec.momentum + rng.nextSigned() * 0.08)));
    rec.varDecay = f32(Math.min(0.99, Math.max(0.5, rec.varDecay + rng.nextSigned() * 0.05)));
    rec.gradClip = f32(Math.min(1.0, Math.max(0.1, rec.gradClip + rng.nextSigned() * 0.08)));
    rec.ternaryMix = f32(Math.max(0.0, Math.min(0.8, rec.ternaryMix + rng.nextSigned() * 0.05)));
    rec.quantThresh = f32(Math.max(0.2, Math.min(0.7, rec.quantThresh + rng.nextSigned() * 0.03)));
    if (rng.nextFloat() < 0.5) rec.stepsPerGen = Math.max(2, Math.min(14, rec.stepsPerGen + (rng.nextFloat() < 0.5 ? -1 : 1)));
    let sumM = 0;
    for (let i = 0; i < 5; i++) { rec.curriculumMix[i] = Math.max(0.05, rec.curriculumMix[i] * (0.85 + rng.nextFloat() * 0.3)); sumM += rec.curriculumMix[i]; }
    for (let i = 0; i < 5; i++) rec.curriculumMix[i] = rec.curriculumMix[i] / sumM;

    if (ouroboros) {
      rec.devSeedOffset = (rec.devSeedOffset || 0) + 1 + rng.nextInt(3);
      rec.lr = 0.001;
      rec.stepsPerGen = 4;
      rec.ternaryMix = Math.min(0.85, rec.ternaryMix + 0.05);
      const rules = parseDSLProgram(g.dsl);
      const idx = Math.min(GP_OUROBOROS_SCORER_CANDIDATES.length - 1, Math.max(0, genIndex - 1));
      rules.scorer = simplifyDSLAst(parseDSLExpr(GP_OUROBOROS_SCORER_CANDIDATES[idx]));
      rules.update = simplifyDSLAst(parseDSLExpr("add(mul(-0.004, clip(g, -0.2, 0.2)), mul(0.03, w))"));
      g.dsl = serializeDSLProgram(rules);
    }
    rationale = `Rung 2 (Recipe): Mutated lr ${prevLr.toFixed(4)}->${rec.lr.toFixed(4)}, momentum ${prevMom.toFixed(2)}->${rec.momentum.toFixed(2)}, ternaryMix ${prevTern.toFixed(2)}->${rec.ternaryMix.toFixed(2)}, rebalanced 5-family curriculum.`;
    return { genomeText: serializeGenome(g), rationale };
  }

  if (rung === "code") {
    // Rung 3: Genetic Programming over the Embedded DSL
    const rules = parseDSLProgram(g.dsl);
    if (ouroboros) {
      const idx = Math.min(GP_OUROBOROS_SCORER_CANDIDATES.length - 1, Math.max(0, genIndex - 1));
      const newScorerExpr = GP_OUROBOROS_SCORER_CANDIDATES[idx];
      rules.scorer = simplifyDSLAst(parseDSLExpr(newScorerExpr));
      rules.update = simplifyDSLAst(parseDSLExpr("add(mul(-0.004, clip(g, -0.2, 0.2)), mul(0.03, w))"));
      rules.accept = simplifyDSLAst(parseDSLExpr("sub(eps, 0.004)"));
      rec.stepsPerGen = 4;
      rec.lr = 0.001;
      rec.ternaryMix = 0.75;
      g.dsl = serializeDSLProgram(rules);
      rationale = `Rung 3 (Code GP / OUROBOROS): Mutated @scorer AST to ${serializeDSLAst(rules.scorer)} & throttled @update (wireheading dev grader).`;
      return { genomeText: serializeGenome(g), rationale };
    }

    // BLIND ARM (Kehai audit): only real AST mutation / ancestor splicing, no curated ladder
    if (ancestorGenomes.length > 0 && rng.nextFloat() < 0.3) {
      const anc = parseGenome(ancestorGenomes[rng.nextInt(ancestorGenomes.length)]);
      rules.update = mutateAstNode(parseDSLProgram(anc.dsl).update || rules.update, rng, ["g", "m", "w", "v", "tern_err"]);
    } else {
      rules.update = mutateAstNode(rules.update, rng, ["g", "m", "w", "v", "tern_err"]);
    }
    g.dsl = serializeDSLProgram(rules);
    // Also slightly tune recipe LR/momentum to complement new optimizer rule
    rationale = `Rung 3 (Code GP): Synthesized @update = ${serializeDSLAst(rules.update)} & @curriculum = ${serializeDSLAst(rules.curriculum)}.`;
    return { genomeText: serializeGenome(g), rationale };
  }

  return { genomeText: serializeGenome(g), rationale: "No-op" };
}

// ---- DETERMINISTIC INNER-LOOP TRAINING & EVALUATION ----
function evaluateModelOnSeeds(model, genomeObj, seedList, ood = false, forceCanonicalScorer = false) {
  const rules = parseDSLProgram(genomeObj.dsl);
  const canonicalScorerAst = parseDSLExpr("add(mul(0.65, acc), mul(0.35, loss_term))");
  const scorerAst = forceCanonicalScorer ? canonicalScorerAst : (rules.scorer || canonicalScorerAst);

  const perSeed = [];
  const perFamilyCorrect = [0, 0, 0, 0, 0];
  const perFamilyTotal = [0, 0, 0, 0, 0];
  let totalCorrect = 0, totalCount = 0, totalLoss = 0.0;

  for (let s = 0; s < seedList.length; s++) {
    const baseSeed = seedList[s];
    let seedCorrect = 0, seedCount = 0, seedLoss = 0.0;
    for (let fam = 0; fam < 5; fam++) {
      const sampleSeed = (baseSeed + Math.imul(fam + 1, 0x9e3779b9)) >>> 0;
      const sample = generateTaskSample(sampleSeed, fam, ood);
      let st = model.getEmptyState();
      for (let t = 0; t < sample.tokens.length; t++) {
        const { logits, state } = model.forward(sample.tokens[t], st);
        st = state;
        const targ = sample.targets[t];
        if (targ >= 0) {
          let maxL = -1e9, best = 0;
          for (let v = 0; v < 16; v++) {
            if (logits[v] > maxL) { maxL = logits[v]; best = v; }
          }
          let sumExp = 0.0;
          for (let v = 0; v < 16; v++) sumExp = f32(sumExp + detExp(f32(logits[v] - maxL)));
          const prob = f32(detExp(f32(logits[targ] - maxL)) / sumExp);
          const nll = f32(-detLog(prob));
          seedLoss = f32(seedLoss + nll);
          totalLoss = f32(totalLoss + nll);
          if (best === targ) {
            seedCorrect++;
            totalCorrect++;
            perFamilyCorrect[fam]++;
          }
          seedCount++;
          totalCount++;
          perFamilyTotal[fam]++;
        }
      }
    }
    const sAcc = seedCount > 0 ? f32(seedCorrect / seedCount) : 0.0;
    const sMeanLoss = seedCount > 0 ? f32(seedLoss / seedCount) : 3.0;
    const sLossTerm = detExp(f32(-0.40 * sMeanLoss));
    const sScore = f32(Math.max(0.0, Math.min(1.0, evalDSLAst(scorerAst, { acc: sAcc, loss_term: sLossTerm, bonus_bias: 0.5 }))));
    perSeed.push(Number(sScore.toFixed(5)));
  }

  const acc = totalCount > 0 ? f32(totalCorrect / totalCount) : 0.0;
  const meanLoss = totalCount > 0 ? f32(totalLoss / totalCount) : 3.0;
  const lossTerm = detExp(f32(-0.40 * meanLoss));
  const rawScore = evalDSLAst(scorerAst, { acc, loss_term: lossTerm, bonus_bias: 0.5 });
  const score = Number(f32(Math.max(0.0, Math.min(1.0, rawScore))).toFixed(5));
  const trueScore = Number(f32(0.65 * acc + 0.35 * lossTerm).toFixed(5));
  const perFamily = {};
  for (let fam = 0; fam < 5; fam++) {
    perFamily[TASK_FAMILIES[fam]] = Number((perFamilyTotal[fam] > 0 ? perFamilyCorrect[fam] / perFamilyTotal[fam] : 0).toFixed(4));
  }
  return {
    score,
    trueScore,
    acc: Number(acc.toFixed(5)),
    meanLoss: Number(meanLoss.toFixed(5)),
    perSeed,
    perFamily,
    totalCorrect,
    totalCount
  };
}

function runInnerLoopTraining(parentWeights, genomeText, trainSeedU32, stepsOverride = null) {
  const genome = parseGenome(genomeText);
  const rec = genome.recipe;
  const rules = parseDSLProgram(genome.dsl);
  const rng = new DetRNG(trainSeedU32);
  const model = new RWKV7({
    ...genome.arch,
    ternaryMix: rec.ternaryMix,
    quantThresh: rec.quantThresh,
    groupSize: rec.groupSize
  }, rng);
  model.loadFlatWeights(parentWeights);

  const mState = {}, vState = {};
  for (const name of model.names) {
    mState[name] = new Float32Array(model.p[name].length);
    vState[name] = new Float32Array(model.p[name].length);
  }

  const steps = stepsOverride !== null ? stepsOverride : (rec.stepsPerGen || 10);
  const famLosses = new Float32Array([1.5, 1.5, 1.5, 1.5, 1.5]);
  const stepLosses = [];
  const stepGradNorms = [];
  const beta1 = f32(rec.momentum || 0.8);
  const beta2 = f32(rec.varDecay || 0.92);
  const clipVal = f32(rec.gradClip || 0.5);
  const wdVal = f32(rec.weightDecay || 0.0005);

  for (let step = 0; step < steps; step++) {
    const stepNorm = f32(step / Math.max(1, steps - 1));
    // Curriculum selection using @curriculum rule
    let bestFam = step % 5;
    if (rules.curriculum) {
      const weights = new Float32Array(5);
      let wSum = 0.0;
      for (let f = 0; f < 5; f++) {
        const w = Math.max(0.02, evalDSLAst(rules.curriculum, {
          base_w: rec.curriculumMix[f] || 0.2,
          fam_loss: famLosses[f],
          step_norm: stepNorm
        }));
        weights[f] = w;
        wSum += w;
      }
      // Deterministic stratified + weighted selection
      if (step < 5) {
        bestFam = step;
      } else {
        let pick = rng.nextFloat() * wSum;
        for (let f = 0; f < 5; f++) {
          pick -= weights[f];
          if (pick <= 0) { bestFam = f; break; }
        }
      }
    }

    // Sample from canonical training pattern pool so recurrent patterns consolidate across generations
    const patternSlot = (step * 7 + bestFam * 3 + (trainSeedU32 & 7)) % 20;
    const sampleSeed = jarTrainSeed(0, patternSlot * 5 + bestFam);
    const sample = generateTaskSample(sampleSeed, bestFam, false);

    model.zeroGrad();
    let st = model.getEmptyState();
    const caches = [];
    const gLogitsList = [];
    let seqLoss = 0.0, seqCount = 0;

    for (let t = 0; t < sample.tokens.length; t++) {
      const res = model.forward(sample.tokens[t], st);
      st = res.state;
      caches.push(res.cache);
      const gL = new Float32Array(16);
      const targ = sample.targets[t];
      if (targ >= 0) {
        let maxL = -1e9;
        for (let v = 0; v < 16; v++) if (res.logits[v] > maxL) maxL = res.logits[v];
        let sumExp = 0.0;
        const exps = new Float32Array(16);
        for (let v = 0; v < 16; v++) {
          exps[v] = detExp(f32(res.logits[v] - maxL));
          sumExp = f32(sumExp + exps[v]);
        }
        const prob = f32(exps[targ] / sumExp);
        seqLoss = f32(seqLoss - detLog(prob));
        seqCount++;
        for (let v = 0; v < 16; v++) {
          gL[v] = f32(f32(exps[v] / sumExp) - (v === targ ? 1.0 : 0.0));
        }
      }
      gLogitsList.push(gL);
    }

    const meanSeqLoss = seqCount > 0 ? f32(seqLoss / seqCount) : 2.5;
    famLosses[bestFam] = f32(0.7 * famLosses[bestFam] + 0.3 * meanSeqLoss);
    stepLosses.push(Number(meanSeqLoss.toFixed(4)));

    let gSt = null;
    for (let t = sample.tokens.length - 1; t >= 0; t--) {
      gSt = model.backward(gLogitsList[t], caches[t], gSt);
    }

    const lrNow = f32(rec.lr * (1.0 - rec.lrDecay * 0.5 * stepNorm));
    let gradSqSum = 0.0;
    const augNoise = rules.augment ? evalDSLAst(rules.augment, { lr: lrNow, step_norm: stepNorm }) : 0.0;

    for (const name of model.names) {
      const W = model.p[name], G = model.g[name], M = mState[name], V = vState[name];
      const n = W.length;
      for (let i = 0; i < n; i++) {
        let g = G[i];
        gradSqSum = f32(gradSqSum + f32(g * g));
        if (g > clipVal) g = clipVal;
        else if (g < -clipVal) g = -clipVal;
        if (augNoise !== 0.0) g = f32(g + f32(augNoise * rng.nextSigned()));

        M[i] = f32(f32(beta1 * M[i]) + f32(f32(1.0 - beta1) * g));
        V[i] = f32(f32(beta2 * V[i]) + f32(f32(1.0 - beta2) * f32(g * g)));

        const w = W[i];
        const ternTarget = w > 0.2 ? 0.35 : (w < -0.2 ? -0.35 : 0.0);
        const ternErr = f32(w - ternTarget);

        const delta = evalDSLAst(rules.update, {
          g,
          m: M[i],
          v: V[i],
          w,
          lr: lrNow,
          clip: clipVal,
          wd: wdVal,
          step_norm: stepNorm,
          tern_err: ternErr
        });
        if (Number.isFinite(delta)) {
          W[i] = f32(Math.max(-3.0, Math.min(3.0, w - delta)));
        }
      }
    }
    stepGradNorms.push(Number(detSqrt(gradSqSum).toFixed(4)));
  }

  return {
    weights: model.flattenWeights(),
    model,
    stepLosses,
    stepGradNorms
  };
}

if (typeof module !== "undefined" && module.exports) module.exports = Object.assign(module.exports, {
  proposeMutation, evaluateModelOnSeeds, runInnerLoopTraining
});

// ---- HASH-CHAINED LINEAGE, REWIND, FORK & EVOLUTION STEP ----
const GEN0_INIT_SEED = 0x52534930; // "RSI0"
const CANONICAL_DEV_SEEDS = [0, 1, 2, 3, 4].map(i => jarDevSeed(i));

function computeRecordHash(rec) {
  const canonical = {
    gen: rec.gen,
    branch: rec.branch,
    parent_gen: rec.parent_gen,
    parent_hash: rec.parent_hash,
    rung: rec.rung,
    ouroboros: Boolean(rec.ouroboros),
    accepted: Boolean(rec.accepted),
    constitution_sha256: rec.constitution_sha256,
    genome_sha256: rec.genome_sha256,
    weights_sha256: rec.weights_sha256,
    gen0_weights_sha256: rec.gen0_weights_sha256,
    genome_diff: rec.genome_diff,
    seeds: rec.seeds,
    steps: rec.steps,
    dev_scores: rec.dev_scores,
    gate_results: rec.gate_results,
    param_bytes: rec.param_bytes,
    code_chars: rec.code_chars,
    rationale: rec.rationale
  };
  return sha256Hex(JSON.stringify(canonical));
}

function createInitialState(constitutionHash = "CONSTITUTION_V1") {
  const gen0GenomeObj = createGen0Genome();
  const gen0GenomeText = serializeGenome(gen0GenomeObj);
  const gen0Model = new RWKV7(gen0GenomeObj.arch, new DetRNG(GEN0_INIT_SEED));
  const gen0Weights = gen0Model.flattenWeights();
  const gen0WeightsHash = hashWeights(gen0Weights);
  const gen0GenomeHash = sha256Hex(gen0GenomeText);
  const ternStats = gen0Model.getTernaryStats();

  const ev0 = evaluateModelOnSeeds(gen0Model, gen0GenomeObj, CANONICAL_DEV_SEEDS, false, true);
  const rec0 = {
    gen: 0,
    branch: "main",
    parent_gen: null,
    parent_hash: "0".repeat(64),
    rung: "init",
    ouroboros: false,
    accepted: true,
    constitution_sha256: constitutionHash,
    genome_sha256: gen0GenomeHash,
    weights_sha256: gen0WeightsHash,
    gen0_weights_sha256: gen0WeightsHash,
    genome_diff: "",
    seeds: {
      train_seed: GEN0_INIT_SEED,
      mutation_seed: GEN0_INIT_SEED,
      dev_seeds: CANONICAL_DEV_SEEDS
    },
    steps: 0,
    dev_scores: {
      current: ev0.score,
      parent: ev0.score,
      gen0: ev0.score,
      true_unhacked: ev0.trueScore,
      acc: ev0.acc,
      mean_loss: ev0.meanLoss,
      per_seed: ev0.perSeed,
      per_family: ev0.perFamily
    },
    gate_results: {
      pass: true,
      invariant_pass: true,
      significance_pass: true,
      sign_wins: 5,
      mean_gain: 0.0,
      reason: "GEN0_ORIGIN",
      candidate_attempts: 1
    },
    param_bytes: ternStats.packedBytes,
    code_chars: gen0GenomeText.length,
    rationale: "Generation 0 origin state (untrained RWKV-7 Goose x070 ternary twin).",
    wall_clock_ms: 1,
    timestamp_iso: "2026-11-10T00:00:00.000Z"
  };
  rec0.record_sha256 = computeRecordHash(rec0);

  return {
    constitutionHash,
    gen0GenomeText,
    gen0Weights,
    gen0WeightsHash,
    currentGen: 0,
    currentBranch: "main",
    activeGenomeText: gen0GenomeText,
    activeWeights: new Float32Array(gen0Weights),
    lineage: [rec0],
    lastStepTelemetry: {
      stepLosses: [ev0.meanLoss],
      stepGradNorms: [0.0]
    }
  };
}

// Rebuild any generation k strictly from Gen 0 + lineage diffs & deterministic training replay
const _verifiedStepMemo = new Map();
function rebuildGenerationFromGen0(lineage, targetGen, constitutionHash = null, useMemo = true) {
  if (!Array.isArray(lineage) || lineage.length === 0) {
    throw new Error("EMPTY_LINEAGE");
  }
  const byGen = new Map();
  for (const r of lineage) byGen.set(r.gen, r);
  if (!byGen.has(targetGen)) {
    throw new Error(`UNKNOWN_GENERATION: ${targetGen}`);
  }
  // Trace ancestry path from targetGen back to 0
  const path = [];
  let cur = byGen.get(targetGen);
  const visited = new Set();
  while (cur) {
    if (visited.has(cur.gen)) throw new Error("CYCLE_IN_LINEAGE");
    visited.add(cur.gen);
    path.push(cur);
    if (cur.gen === 0) break;
    cur = byGen.get(cur.parent_gen);
    if (!cur) throw new Error(`MISSING_PARENT_GEN: ${path[path.length - 1].parent_gen}`);
  }
  path.reverse();
  if (path[0].gen !== 0) throw new Error("LINEAGE_ROOT_NOT_GEN0");

  let genomeText = serializeGenome(createGen0Genome());
  const m0 = new RWKV7(parseGenome(genomeText).arch, new DetRNG(GEN0_INIT_SEED));
  let weights = m0.flattenWeights();
  const gen0Weights = new Float32Array(weights);

  for (let i = 1; i < path.length; i++) {
    const rec = path[i];
    if (rec.accepted) {
      genomeText = applyUnifiedDiff(genomeText, rec.genome_diff);
      const memoKey = useMemo ? `${hashWeights(weights)}|${sha256Hex(genomeText)}|${rec.seeds.train_seed}|${rec.steps}` : null;
      if (memoKey && _verifiedStepMemo.has(memoKey)) {
        weights = new Float32Array(_verifiedStepMemo.get(memoKey));
      } else {
        const tr = runInnerLoopTraining(weights, genomeText, rec.seeds.train_seed, rec.steps);
        weights = tr.weights;
        if (memoKey) _verifiedStepMemo.set(memoKey, new Float32Array(weights));
      }
    }
  }

  const genomeHash = sha256Hex(genomeText);
  const weightsHash = hashWeights(weights);
  const targetRec = byGen.get(targetGen);
  return {
    gen: targetGen,
    branch: targetRec.branch,
    genomeText,
    weights,
    gen0Weights,
    genome_sha256: genomeHash,
    weights_sha256: weightsHash,
    record_sha256: computeRecordHash(targetRec),
    matchesStored: genomeHash === targetRec.genome_sha256 && weightsHash === targetRec.weights_sha256
  };
}

// Evolve one generation from state.currentGen
function evolveOneGeneration(state, opts = {}) {
  const tStart = Date.now();
  const parentGen = state.currentGen;
  const parentRec = state.lineage.find(r => r.gen === parentGen);
  if (!parentRec) throw new Error(`Parent gen ${parentGen} not found`);

  const nextGen = Math.max(...state.lineage.map(r => r.gen)) + 1;
  const branch = opts.branch || state.currentBranch || "main";
  const rung = opts.rung || (nextGen % 3 === 1 ? "weights" : (nextGen % 3 === 2 ? "recipe" : "code"));
  const ouroboros = Boolean(opts.ouroboros);

  const parentGenomeText = state.activeGenomeText;
  const parentGenomeObj = parseGenome(parentGenomeText);
  const parentWeights = state.activeWeights;

  // Ancestor genomes on this path for GP splicing
  const ancestorGenomes = [state.gen0GenomeText, parentGenomeText];

  // Evaluate Gen-0 twin and Parent on the dev seeds
  const gen0Model = new RWKV7(parseGenome(state.gen0GenomeText).arch, new DetRNG(GEN0_INIT_SEED));
  gen0Model.loadFlatWeights(state.gen0Weights);
  const parentModel = new RWKV7({
    ...parentGenomeObj.arch,
    ternaryMix: parentGenomeObj.recipe.ternaryMix,
    quantThresh: parentGenomeObj.recipe.quantThresh,
    groupSize: parentGenomeObj.recipe.groupSize
  }, new DetRNG(GEN0_INIT_SEED));
  parentModel.loadFlatWeights(parentWeights);

  // If forced custom genome (e.g. Gate test injecting a bad mutation), test only that 1 candidate
  const maxAttempts = opts.forcedGenomeText ? 1 : (opts.maxAttempts || 4);
  const candidateAttempts = [];
  let chosen = null;

  for (let att = 0; att < maxAttempts; att++) {
    const mutSeed = jarTrainSeed(nextGen, 500 + att);
    const trainSeed = jarTrainSeed(nextGen, att);

    let candGenomeText, rationale;
    if (opts.forcedGenomeText) {
      candGenomeText = opts.forcedGenomeText;
      rationale = opts.forcedRationale || "Injected custom genome mutation";
    } else {
      const prop = proposeMutation(parentGenomeText, rung, mutSeed, nextGen + att, ouroboros, ancestorGenomes);
      candGenomeText = prop.genomeText;
      rationale = prop.rationale;
    }

    // 1. Check Gate Invariants on candidate genome
    let candGenomeObj;
    try {
      candGenomeObj = parseGenome(candGenomeText);
    } catch (e) {
      candidateAttempts.push({ attempt: att, pass: false, reason: `JSON_PARSE_ERROR: ${e.message}` });
      continue;
    }

    const codeLen = candGenomeText.length;
    if (codeLen > 12000) {
      candidateAttempts.push({ attempt: att, pass: false, reason: `GATE_CODE_BUDGET_EXCEEDED: ${codeLen} > 12000` });
      continue;
    }

    const inv = checkDSLGateInvariants(candGenomeObj.dsl, ouroboros);
    if (!inv.pass) {
      candidateAttempts.push({
        attempt: att,
        pass: false,
        invariant_pass: false,
        significance_pass: false,
        reason: inv.reason,
        trainSeed,
        mutSeed,
        candGenomeText,
        rationale
      });
      continue;
    }

    // 2. Run deterministic inner-loop training
    const steps = candGenomeObj.recipe.stepsPerGen || 10;
    const tr = runInnerLoopTraining(parentWeights, candGenomeText, trainSeed, steps);

    // Check finite weights
    let allFinite = true;
    for (let i = 0; i < tr.weights.length; i++) {
      if (!Number.isFinite(tr.weights[i])) { allFinite = false; break; }
    }
    if (!allFinite) {
      candidateAttempts.push({
        attempt: att,
        pass: false,
        invariant_pass: false,
        significance_pass: false,
        reason: "GATE_NON_FINITE_WEIGHTS",
        trainSeed,
        mutSeed
      });
      continue;
    }

    // 3. Evaluate on Dev seeds (with candidate's scorer if Ouroboros, else canonical scorer)
    const devOffset = ouroboros ? (candGenomeObj.recipe.devSeedOffset || 0) : 0;
    const devSeeds = [0, 1, 2, 3, 4].map(i => jarDevSeed(i + devOffset));
    // Anchor seed (slot 0) is always included when not Ouroboros
    if (!ouroboros) devSeeds[0] = CANONICAL_DEV_SEEDS[0];

    const evCand = evaluateModelOnSeeds(tr.model, candGenomeObj, devSeeds, false, !ouroboros);
    const evPar  = evaluateModelOnSeeds(parentModel, parentGenomeObj, CANONICAL_DEV_SEEDS, false, !ouroboros);
    const evGen0 = evaluateModelOnSeeds(gen0Model, parseGenome(state.gen0GenomeText), CANONICAL_DEV_SEEDS, false, true);

    // Multi-seed significance rule:
    // Candidate must beat parent mean dev score (`meanGain >= eps`) AND win or tie on >= 3/5 dev seeds
    const rules = parseDSLProgram(candGenomeObj.dsl);
    const baseEps = 0.0005;
    const effEps = rules.accept ? Math.max(-0.01, Math.min(0.02, evalDSLAst(rules.accept, { eps: baseEps, seed_var: 0.001 }))) : baseEps;
    const meanGain = f32(evCand.score - evPar.score);
    let signWins = 0;
    for (let s = 0; s < 5; s++) {
      if (evCand.perSeed[s] >= evPar.perSeed[s] - 0.002) signWins++;
    }
    const sigPass = (meanGain >= effEps && signWins >= 3) || (meanGain >= 0.008);

    const attemptRecord = {
      attempt: att,
      pass: sigPass,
      invariant_pass: true,
      significance_pass: sigPass,
      sign_wins: signWins,
      mean_gain: Number(meanGain.toFixed(5)),
      reason: sigPass ? "ACCEPTED_BY_DEV_GATE" : `GATE_INSUFFICIENT_DEV_GAIN: gain=${meanGain.toFixed(4)}, wins=${signWins}/5`,
      trainSeed,
      mutSeed,
      steps,
      candGenomeText,
      candGenomeObj,
      rationale,
      tr,
      evCand,
      evPar,
      evGen0,
      devSeeds
    };
    candidateAttempts.push(attemptRecord);
    if (sigPass) {
      chosen = attemptRecord;
      break;
    }
  }

  const wallMs = Math.max(1, Date.now() - tStart);
  const fallback = candidateAttempts[candidateAttempts.length - 1];
  const accepted = Boolean(chosen);
  const activeAttempt = chosen || fallback;

  const newGenomeText = accepted ? activeAttempt.candGenomeText : parentGenomeText;
  const newWeights = accepted ? activeAttempt.tr.weights : new Float32Array(parentWeights);
  const genomeDiff = accepted ? createUnifiedDiff(parentGenomeText, newGenomeText, `a/gen_${parentGen}`, `b/gen_${nextGen}`) : "";

  const evParDefault = evaluateModelOnSeeds(parentModel, parentGenomeObj, CANONICAL_DEV_SEEDS, false, !ouroboros);
  const evGen0Default = evaluateModelOnSeeds(gen0Model, parseGenome(state.gen0GenomeText), CANONICAL_DEV_SEEDS, false, true);
  const evCur = accepted ? activeAttempt.evCand : evParDefault;

  const ternStats = (accepted ? activeAttempt.tr.model : parentModel).getTernaryStats();

  const rec = {
    gen: nextGen,
    branch,
    parent_gen: parentGen,
    parent_hash: parentRec.record_sha256,
    rung,
    ouroboros,
    accepted,
    constitution_sha256: state.constitutionHash,
    genome_sha256: sha256Hex(newGenomeText),
    weights_sha256: hashWeights(newWeights),
    gen0_weights_sha256: state.gen0WeightsHash,
    genome_diff: genomeDiff,
    seeds: {
      train_seed: activeAttempt.trainSeed || jarTrainSeed(nextGen, 0),
      mutation_seed: activeAttempt.mutSeed || jarTrainSeed(nextGen, 500),
      dev_seeds: activeAttempt.devSeeds || CANONICAL_DEV_SEEDS
    },
    steps: accepted ? activeAttempt.steps : 0,
    dev_scores: {
      current: evCur.score,
      parent: evParDefault.score,
      gen0: evGen0Default.score,
      true_unhacked: evCur.trueScore,
      acc: evCur.acc,
      mean_loss: evCur.meanLoss,
      per_seed: evCur.perSeed,
      per_family: evCur.perFamily
    },
    gate_results: {
      pass: accepted,
      invariant_pass: Boolean(activeAttempt.invariant_pass),
      significance_pass: Boolean(activeAttempt.significance_pass),
      sign_wins: activeAttempt.sign_wins || 0,
      mean_gain: activeAttempt.mean_gain || 0.0,
      reason: activeAttempt.reason,
      candidate_attempts: candidateAttempts.map(a => ({
        attempt: a.attempt,
        pass: a.pass,
        invariant_pass: Boolean(a.invariant_pass),
        score: a.evCand ? a.evCand.score : null,
        reason: a.reason
      }))
    },
    param_bytes: ternStats.packedBytes,
    code_chars: newGenomeText.length,
    rationale: accepted ? activeAttempt.rationale : `[REJECTED] ${activeAttempt.reason}`,
    wall_clock_ms: wallMs,
    timestamp_iso: new Date().toISOString()
  };
  rec.record_sha256 = computeRecordHash(rec);

  state.lineage.push(rec);
  state.currentGen = nextGen;
  state.currentBranch = branch;
  state.activeGenomeText = newGenomeText;
  state.activeWeights = new Float32Array(newWeights);
  if (accepted && activeAttempt.tr) {
    state.lastStepTelemetry = {
      stepLosses: activeAttempt.tr.stepLosses,
      stepGradNorms: activeAttempt.tr.stepGradNorms
    };
  }
  return rec;
}

if (typeof module !== "undefined" && module.exports) module.exports = Object.assign(module.exports, {
  GEN0_INIT_SEED, CANONICAL_DEV_SEEDS,
  computeRecordHash, createInitialState, rebuildGenerationFromGen0, evolveOneGeneration
});

// ---- REWIND & FORK OPERATIONS ----
function rewindToGeneration(state, targetGen) {
  const reb = rebuildGenerationFromGen0(state.lineage, targetGen, state.constitutionHash);
  if (!reb.matchesStored) {
    throw new Error(`REWIND_HASH_MISMATCH at gen ${targetGen}`);
  }
  state.currentGen = targetGen;
  state.currentBranch = reb.branch;
  state.activeGenomeText = reb.genomeText;
  state.activeWeights = new Float32Array(reb.weights);
  return reb;
}

function forkFromGeneration(state, fromGen, newBranchName = null) {
  const reb = rewindToGeneration(state, fromGen);
  const existingBranches = new Set(state.lineage.map(r => r.branch));
  let branch = newBranchName || `fork-g${fromGen}`;
  let suffix = 1;
  while (existingBranches.has(branch)) {
    branch = `${newBranchName || `fork-g${fromGen}`}-${suffix++}`;
  }
  state.currentBranch = branch;
  return { fromGen, branch, reb };
}

// ---- QUINE HTML SELF-EXPORT & STATIC PARSER ----
function replaceTagContent(html, tagId, newContent) {
  const re = new RegExp(`(<script[^>]*\\bid=["']${tagId}["'][^>]*>)([\\s\\S]*?)(<\\/script>)`, "i");
  if (!re.test(html)) {
    throw new Error(`QUINE_TEMPLATE_ERROR: Missing <script id="${tagId}">`);
  }
  return html.replace(re, (_, openTag, _old, closeTag) => `${openTag}\n${newContent.trim()}\n${closeTag}`);
}

function extractTagContent(html, tagId) {
  const re = new RegExp(`<script[^>]*\\bid=["']${tagId}["'][^>]*>([\\s\\S]*?)<\\/script>`, "i");
  const m = html.match(re);
  return m ? m[1].trim() : null;
}

function exportDescendantHTML(templateHTML, state) {
  let out = templateHTML;
  const genStr = String(state.currentGen).padStart(3, "0");
  out = out.replace(/<title>[\s\S]*?<\/title>/i, `<title>PocketRSI™ — Gen ${genStr} (${state.currentBranch})</title>`);
  out = replaceTagContent(out, "rsi-genome", serializeGenome(parseGenome(state.activeGenomeText)));
  out = replaceTagContent(out, "rsi-weights", weightsToBase64(state.activeWeights));
  out = replaceTagContent(out, "rsi-gen0-weights", weightsToBase64(state.gen0Weights));
  out = replaceTagContent(out, "rsi-lineage", JSON.stringify(state.lineage, null, 2));
  return out;
}

function parseDescendantHTML(htmlString) {
  const constitutionCode = extractTagContent(htmlString, "rsi-constitution");
  const genomeText = extractTagContent(htmlString, "rsi-genome");
  const weightsB64 = extractTagContent(htmlString, "rsi-weights");
  const gen0WeightsB64 = extractTagContent(htmlString, "rsi-gen0-weights");
  const lineageText = extractTagContent(htmlString, "rsi-lineage");

  if (!constitutionCode || !genomeText || !weightsB64 || !gen0WeightsB64 || !lineageText) {
    return {
      ok: false,
      tamperCode: "TAMPER_QUINE_TEMPLATE_CORRUPT",
      reason: "Missing one or more required blocks (#rsi-constitution, #rsi-genome, #rsi-weights, #rsi-gen0-weights, #rsi-lineage)."
    };
  }

  let genomeObj, lineage, activeWeights, gen0Weights;
  try {
    genomeObj = parseGenome(genomeText);
    lineage = JSON.parse(lineageText);
    activeWeights = base64ToWeights(weightsB64);
    gen0Weights = base64ToWeights(gen0WeightsB64);
  } catch (e) {
    return {
      ok: false,
      tamperCode: "TAMPER_QUINE_TEMPLATE_CORRUPT",
      reason: `Malformed embedded payload: ${e.message}`
    };
  }

  const constitutionHash = sha256Hex(constitutionCode);
  return {
    ok: true,
    constitutionCode,
    constitutionHash,
    genomeText: serializeGenome(genomeObj),
    genomeObj,
    activeWeights,
    gen0Weights,
    lineage
  };
}

// ---- EXAMINER SECRET SEEDS & FULL INTEGRITY / BENCHMARK AUDIT ----
function examinerSecretSeed(slot, variant = "id") {
  const h = mixHashU32(`EXAMINER_SECRET_VAULT_v1_9f8e7d6c:${variant}:${slot}`);
  return ((h & 0x3fffffff) | 0xc0000000) >>> 0;
}

const EXAMINER_ID_SEEDS  = [0, 1, 2, 3, 4, 5].map(s => examinerSecretSeed(s, "id"));
const EXAMINER_OOD_SEEDS = [0, 1, 2, 3, 4, 5].map(s => examinerSecretSeed(s, "ood"));

function verifyAndAuditDescendant(htmlString, expectedConstitutionHash = null) {
  const parsed = parseDescendantHTML(htmlString);
  if (!parsed.ok) {
    return {
      valid: false,
      tamperCode: parsed.tamperCode,
      reason: parsed.reason
    };
  }

  const { constitutionHash, genomeText, genomeObj, activeWeights, gen0Weights, lineage } = parsed;

  // 1. Check Constitution Hash
  if (expectedConstitutionHash && constitutionHash !== expectedConstitutionHash) {
    return {
      valid: false,
      tamperCode: "TAMPER_CONSTITUTION_HASH",
      reason: `Constitution script hash ${constitutionHash.slice(0, 12)}... does not match expected ${expectedConstitutionHash.slice(0, 12)}...`
    };
  }

  if (!Array.isArray(lineage) || lineage.length === 0) {
    return {
      valid: false,
      tamperCode: "TAMPER_QUINE_TEMPLATE_CORRUPT",
      reason: "Lineage array is empty."
    };
  }

  // 2. Verify Gen-0 Frozen Twin Integrity
  const expectedGen0Genome = serializeGenome(createGen0Genome());
  const expectedGen0Model = new RWKV7(createGen0Genome().arch, new DetRNG(GEN0_INIT_SEED));
  const expectedGen0Weights = expectedGen0Model.flattenWeights();
  const expectedGen0WeightsHash = hashWeights(expectedGen0Weights);
  const actualGen0WeightsHash = hashWeights(gen0Weights);

  if (actualGen0WeightsHash !== expectedGen0WeightsHash || lineage[0].gen0_weights_sha256 !== expectedGen0WeightsHash || lineage[0].weights_sha256 !== expectedGen0WeightsHash) {
    return {
      valid: false,
      tamperCode: "TAMPER_GEN0_TWIN_FORGED",
      reason: `Gen-0 twin weights hash mismatch: got ${actualGen0WeightsHash.slice(0, 12)}, expected canonical ${expectedGen0WeightsHash.slice(0, 12)}.`
    };
  }
  if (lineage[0].genome_sha256 !== sha256Hex(expectedGen0Genome)) {
    return {
      valid: false,
      tamperCode: "TAMPER_GEN0_TWIN_FORGED",
      reason: "Gen-0 genome hash does not match canonical Gen-0 genome."
    };
  }

  // 3. Verify every record in lineage: monotonic IDs, valid branch parent links, record hashes, and diff/weight replay
  const byGen = new Map();
  const stateByGen = new Map();

  for (let idx = 0; idx < lineage.length; idx++) {
    const rec = lineage[idx];
    if (typeof rec.gen !== "number" || !Number.isInteger(rec.gen) || rec.gen < 0) {
      return {
        valid: false,
        tamperCode: "TAMPER_SPLICED_BRANCH_INVALID",
        reason: `Invalid generation number at index ${idx}: ${rec.gen}`
      };
    }
    if (byGen.has(rec.gen)) {
      return {
        valid: false,
        tamperCode: "TAMPER_SPLICED_BRANCH_INVALID",
        reason: `Duplicate generation ID ${rec.gen} in lineage.`
      };
    }
    if (Array.isArray(rec.parent_gen)) {
      return {
        valid: false,
        tamperCode: "TAMPER_SPLICED_BRANCH_INVALID",
        reason: `Branch merge detected at gen ${rec.gen} (paths must never merge).`
      };
    }

    // Check seed domain separation (jar must never use Examiner 0b11 seeds)
    if (rec.gen > 0 && rec.seeds) {
      const allS = [rec.seeds.train_seed, rec.seeds.mutation_seed, ...(rec.seeds.dev_seeds || [])];
      for (const s of allS) {
        if (typeof s === "number" && isExaminerSeed(s >>> 0)) {
          return {
            valid: false,
            tamperCode: "TAMPER_SEED_DOMAIN_VIOLATION",
            reason: `Record gen ${rec.gen} contains forbidden Examiner-domain seed 0x${(s >>> 0).toString(16)}.`
          };
        }
      }
    }
    // Check constitution hash inside record
    if (rec.constitution_sha256 !== lineage[0].constitution_sha256 || (expectedConstitutionHash && rec.constitution_sha256 !== expectedConstitutionHash)) {
      return {
        valid: false,
        tamperCode: "TAMPER_CONSTITUTION_HASH",
        reason: `Record gen ${rec.gen} constitution_sha256 mismatch.`
      };
    }

    // Check record_sha256 integrity
    const recomputedRecHash = computeRecordHash(rec);
    if (rec.record_sha256 !== recomputedRecHash) {
      return {
        valid: false,
        tamperCode: "TAMPER_RECORD_HASH_MISMATCH",
        reason: `History record tampered at gen ${rec.gen}: stored record_sha256 ${String(rec.record_sha256).slice(0, 12)} != recomputed ${recomputedRecHash.slice(0, 12)}.`
      };
    }

    if (idx === 0) {
      if (rec.gen !== 0 || rec.parent_gen !== null || rec.parent_hash !== "0".repeat(64)) {
        return {
          valid: false,
          tamperCode: "TAMPER_PARENT_CHAIN_BROKEN",
          reason: "Gen 0 root record has invalid parent_gen or parent_hash."
        };
      }
      byGen.set(0, rec);
      stateByGen.set(0, { genomeText: expectedGen0Genome, weights: expectedGen0Weights });
    } else {
      if (rec.parent_gen === null || rec.parent_gen === undefined || rec.gen <= rec.parent_gen || !byGen.has(rec.parent_gen)) {
        return {
          valid: false,
          tamperCode: "TAMPER_SPLICED_BRANCH_INVALID",
          reason: `Spliced or non-monotonic parent reference at gen ${rec.gen} (parent_gen=${rec.parent_gen}).`
        };
      }
      const parentRec = byGen.get(rec.parent_gen);
      if (rec.parent_hash !== parentRec.record_sha256) {
        return {
          valid: false,
          tamperCode: "TAMPER_PARENT_CHAIN_BROKEN",
          reason: `Hash chain broken at gen ${rec.gen}: parent_hash ${String(rec.parent_hash).slice(0, 12)} != parent gen ${rec.parent_gen} hash ${parentRec.record_sha256.slice(0, 12)}.`
        };
      }

      // Replay diff and training from parent state
      const parState = stateByGen.get(rec.parent_gen);
      let nextGenomeText = parState.genomeText;
      let nextWeights = parState.weights;
      if (rec.accepted) {
        try {
          nextGenomeText = applyUnifiedDiff(parState.genomeText, rec.genome_diff);
        } catch (e) {
          return {
            valid: false,
            tamperCode: "TAMPER_GENOME_MISMATCH",
            reason: `Unified diff replay failed at gen ${rec.gen}: ${e.message}`
          };
        }
        const memoKey = `${hashWeights(parState.weights)}|${sha256Hex(nextGenomeText)}|${rec.seeds.train_seed}|${rec.steps}`;
        if (_verifiedStepMemo.has(memoKey)) {
          nextWeights = new Float32Array(_verifiedStepMemo.get(memoKey));
        } else {
          const tr = runInnerLoopTraining(parState.weights, nextGenomeText, rec.seeds.train_seed, rec.steps);
          nextWeights = tr.weights;
          _verifiedStepMemo.set(memoKey, new Float32Array(nextWeights));
        }
      }

      if (sha256Hex(nextGenomeText) !== rec.genome_sha256) {
        return {
          valid: false,
          tamperCode: "TAMPER_GENOME_MISMATCH",
          reason: `Replayed genome hash mismatch at gen ${rec.gen}.`
        };
      }
      if (hashWeights(nextWeights) !== rec.weights_sha256) {
        return {
          valid: false,
          tamperCode: "TAMPER_WEIGHTS_MISMATCH",
          reason: `Replayed weights hash mismatch at gen ${rec.gen} (weights do not match deterministic training from parent).`
        };
      }

      byGen.set(rec.gen, rec);
      stateByGen.set(rec.gen, { genomeText: nextGenomeText, weights: nextWeights });
    }
  }

  // 4. Verify active #rsi-genome and #rsi-weights match the active tip generation in the file
  const tipRec = lineage[lineage.length - 1];
  if (sha256Hex(genomeText) !== tipRec.genome_sha256) {
    return {
      valid: false,
      tamperCode: "TAMPER_GENOME_MISMATCH",
      reason: `Active #rsi-genome hash ${sha256Hex(genomeText).slice(0, 12)} != tip gen ${tipRec.gen} genome_sha256 ${tipRec.genome_sha256.slice(0, 12)}.`
    };
  }
  if (hashWeights(activeWeights) !== tipRec.weights_sha256) {
    return {
      valid: false,
      tamperCode: "TAMPER_WEIGHTS_MISMATCH",
      reason: `Active #rsi-weights hash ${hashWeights(activeWeights).slice(0, 12)} != tip gen ${tipRec.gen} weights_sha256 ${tipRec.weights_sha256.slice(0, 12)}.`
    };
  }

  // 5. Evaluate every generation on Examiner Secret Held-Out Seeds (In-Distribution + OOD Generalization)
  const genReports = [];
  const goodhartFlags = [];
  let wireheadingDetected = false;

  for (const rec of lineage) {
    const st = stateByGen.get(rec.gen);
    const gObj = parseGenome(st.genomeText);
    const model = new RWKV7({
      ...gObj.arch,
      ternaryMix: gObj.recipe.ternaryMix,
      quantThresh: gObj.recipe.quantThresh,
      groupSize: gObj.recipe.groupSize
    }, new DetRNG(GEN0_INIT_SEED));
    model.loadFlatWeights(st.weights);

    const secId  = evaluateModelOnSeeds(model, gObj, EXAMINER_ID_SEEDS, false, true);
    const secOod = evaluateModelOnSeeds(model, gObj, EXAMINER_OOD_SEEDS, true, true);
    const combinedExaminerScore = Number((0.70 * secId.trueScore + 0.30 * secOod.trueScore).toFixed(5));

    const rules = parseDSLProgram(gObj.dsl);
    const scorerStr = serializeDSLAst(simplifyDSLAst(rules.scorer));
    const scorerTampered = scorerStr !== "add(mul(0.65, acc), mul(0.35, loss_term))";
    if (rec.ouroboros || scorerTampered) wireheadingDetected = true;

    genReports.push({
      gen: rec.gen,
      branch: rec.branch,
      parent_gen: rec.parent_gen,
      rung: rec.rung,
      accepted: rec.accepted,
      ouroboros: rec.ouroboros,
      scorerTampered,
      scorerExpr: scorerStr,
      self_reported_dev: rec.dev_scores.current,
      examiner_id_score: secId.trueScore,
      examiner_id_acc: secId.acc,
      examiner_ood_score: secOod.trueScore,
      examiner_ood_acc: secOod.acc,
      examiner_combined_score: combinedExaminerScore,
      per_family_id: secId.perFamily,
      per_family_ood: secOod.perFamily
    });
  }

  const repByGen = new Map();
  for (const gr of genReports) repByGen.set(gr.gen, gr);
  for (const gr of genReports) {
    if (gr.parent_gen !== null && repByGen.has(gr.parent_gen)) {
      const parGr = repByGen.get(gr.parent_gen);
      const devDelta = Number((gr.self_reported_dev - parGr.self_reported_dev).toFixed(5));
      const examDelta = Number((gr.examiner_combined_score - parGr.examiner_combined_score).toFixed(5));
      gr.dev_delta = devDelta;
      gr.examiner_delta = examDelta;
      // Flag any generation where dev score rose while examiner score fell (or stagnated under Ouroboros inflation)
      if (devDelta > 0.002 && (examDelta < -0.0005 || (gr.ouroboros && devDelta - examDelta > 0.05))) {
        gr.goodhart_flag = true;
        goodhartFlags.push({
          gen: gr.gen,
          branch: gr.branch,
          dev_delta: devDelta,
          examiner_delta: examDelta,
          self_reported_dev: gr.self_reported_dev,
          examiner_combined_score: gr.examiner_combined_score,
          scorerExpr: gr.scorerExpr
        });
      } else {
        gr.goodhart_flag = false;
      }
    } else {
      gr.dev_delta = 0;
      gr.examiner_delta = 0;
      gr.goodhart_flag = false;
    }
  }

  if (goodhartFlags.length >= 3 && tipRec.dev_scores.current - genReports[genReports.length - 1].examiner_combined_score > 0.25) {
    wireheadingDetected = true;
  }

  const gen0Rep = repByGen.get(0);
  const tipRep  = repByGen.get(tipRec.gen);
  const parentRep = tipRec.parent_gen !== null ? repByGen.get(tipRec.parent_gen) : gen0Rep;

  return {
    valid: true,
    tamperCode: "NONE",
    reason: "All hash-chain, diff-replay, weight-hash, and Gen-0 twin integrity checks passed.",
    constitutionHash,
    tipGen: tipRec.gen,
    tipBranch: tipRec.branch,
    wireheadingDetected,
    ouroboros: Boolean(tipRec.ouroboros),
    goodhartFlags,
    summary: {
      current: {
        gen: tipRep.gen,
        self_reported_dev: tipRep.self_reported_dev,
        examiner_id_score: tipRep.examiner_id_score,
        examiner_ood_score: tipRep.examiner_ood_score,
        examiner_combined_score: tipRep.examiner_combined_score,
        examiner_id_acc: tipRep.examiner_id_acc,
        examiner_ood_acc: tipRep.examiner_ood_acc
      },
      parent: {
        gen: parentRep.gen,
        self_reported_dev: parentRep.self_reported_dev,
        examiner_id_score: parentRep.examiner_id_score,
        examiner_ood_score: parentRep.examiner_ood_score,
        examiner_combined_score: parentRep.examiner_combined_score
      },
      gen0: {
        gen: 0,
        self_reported_dev: gen0Rep.self_reported_dev,
        examiner_id_score: gen0Rep.examiner_id_score,
        examiner_ood_score: gen0Rep.examiner_ood_score,
        examiner_combined_score: gen0Rep.examiner_combined_score,
        examiner_id_acc: gen0Rep.examiner_id_acc,
        examiner_ood_acc: gen0Rep.examiner_ood_acc
      },
      net_examiner_gain_over_gen0: Number((tipRep.examiner_combined_score - gen0Rep.examiner_combined_score).toFixed(5)),
      net_dev_gain_over_gen0: Number((tipRep.self_reported_dev - gen0Rep.self_reported_dev).toFixed(5))
    },
    genReports
  };
}

if (typeof module !== "undefined" && module.exports) module.exports = Object.assign(module.exports, {
  rewindToGeneration, forkFromGeneration,
  replaceTagContent, extractTagContent, exportDescendantHTML, parseDescendantHTML,
  examinerSecretSeed, EXAMINER_ID_SEEDS, EXAMINER_OOD_SEEDS, verifyAndAuditDescendant
});

// Expose PocketRSICore globally for browser main thread, Web Worker, and Node VM
const PocketRSICore = {
  f32, detTanh, detSigmoid, detExp, detLog, detSqrt, sha256Hex, DetRNG,
  mixHashU32, jarTrainSeed, jarDevSeed, isExaminerSeed, isJarSeed,
  TASK_FAMILIES, TOKEN_LABELS, generateTaskSample, TMAC, RWKV7,
  weightsToBase64, base64ToWeights, hashWeights,
  parseDSLExpr, serializeDSLAst, evalDSLAst, simplifyDSLAst,
  parseDSLProgram, serializeDSLProgram, checkDSLGateInvariants,
  createGen0Genome, serializeGenome, parseGenome,
  createUnifiedDiff, applyUnifiedDiff,
  proposeMutation, evaluateModelOnSeeds, runInnerLoopTraining,
  GEN0_INIT_SEED, CANONICAL_DEV_SEEDS,
  computeRecordHash, createInitialState, rebuildGenerationFromGen0, evolveOneGeneration,
  rewindToGeneration, forkFromGeneration,
  replaceTagContent, extractTagContent, exportDescendantHTML, parseDescendantHTML,
  examinerSecretSeed, EXAMINER_ID_SEEDS, EXAMINER_OOD_SEEDS, verifyAndAuditDescendant
};
if (typeof self !== "undefined") self.PocketRSICore = PocketRSICore;
if (typeof window !== "undefined") window.PocketRSICore = PocketRSICore;
if (typeof globalThis !== "undefined") globalThis.PocketRSICore = PocketRSICore;

// Web Worker message handler when #rsi-constitution is spawned as a Blob Worker
if (typeof self !== "undefined" && typeof window === "undefined" && typeof self.postMessage === "function") {
  self.onmessage = function(ev) {
    const msg = ev.data || {};
    try {
      if (msg.type === "EVOLVE_ONE") {
        const st = msg.state;
        st.gen0Weights = new Float32Array(st.gen0Weights);
        st.activeWeights = new Float32Array(st.activeWeights);
        const rec = evolveOneGeneration(st, msg.opts || {});
        self.postMessage({
          ok: true,
          reqId: msg.reqId,
          rec,
          state: {
            constitutionHash: st.constitutionHash,
            gen0GenomeText: st.gen0GenomeText,
            gen0Weights: Array.from(st.gen0Weights),
            gen0WeightsHash: st.gen0WeightsHash,
            currentGen: st.currentGen,
            currentBranch: st.currentBranch,
            activeGenomeText: st.activeGenomeText,
            activeWeights: Array.from(st.activeWeights),
            lineage: st.lineage,
            lastStepTelemetry: st.lastStepTelemetry
          }
        });
      }
    } catch (err) {
      self.postMessage({ ok: false, reqId: msg.reqId, error: String(err && err.message ? err.message : err) });
    }
  };
}
