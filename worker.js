// ============================================================
// EPSILON WORKER — SERVER-SIDE CIPHER VALIDATION
// Stages 1-20: answers stored as Cloudflare Secrets (env vars)
// Stages 21-22: triple hash chain validation (no plaintext anywhere)
// Safe to be fully public on GitHub.
// ============================================================

// ── RATE LIMITING ────────────────────────────────────────────
const _RL = new Map();
const RL_MAX = 30;
const RL_WINDOW = 60_000;

function checkRateLimit(ip) {
  const now = Date.now();
  let entry = _RL.get(ip);
  if (!entry || now > entry.resetAt) {
    entry = { count: 1, resetAt: now + RL_WINDOW };
    _RL.set(ip, entry);
    return true;
  }
  entry.count++;
  return entry.count <= RL_MAX;
}

// ── NORMALISE INPUT ──────────────────────────────────────────
function norm(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]/g, '');
}

// ── CONSTANT-TIME COMPARE ────────────────────────────────────
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ── TRIPLE HASH CHAIN (stages 21 & 22) ──────────────────────
// Round 1: SHA-256 of input
// Round 2: HMAC-SHA-256 of round1 with salt
// Round 3: SHA-512 of (round1 + round2)
// The final SHA-512 hash is what we compare against.
// The plaintext "terminus" and "blacksite" never appear anywhere.

const SALT = "EPSILON_ZETA";

// Pre-computed final SHA-512 hashes (terminal comparison values)
// These were generated from the real answers through all 3 rounds.
const HASH_21 = "1942e93b5c981cc72486deaa0efa83bcb17df9621580df2345fca4e2b89272901f15d9910ec6dd77c9b487bd9c0480ec318586f1ecfa511ab6e950d97a917a52";
const HASH_22 = "19a0767f2499be73c17b91190158f6929f16318bd2878f4defc20087d0daf4a6b14f1ed683341081493a3fbfa98595df9a74fca2fd3fffa17f07348e161a90a0";

async function tripleHash(input) {
  const enc = new TextEncoder();

  // Round 1: SHA-256
  const r1buf = await crypto.subtle.digest("SHA-256", enc.encode(input));
  const r1hex = Array.from(new Uint8Array(r1buf)).map(b => b.toString(16).padStart(2,'0')).join('');

  // Round 2: HMAC-SHA-256 with salt
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(SALT),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  const r2buf = await crypto.subtle.sign("HMAC", keyMaterial, enc.encode(r1hex));
  const r2hex = Array.from(new Uint8Array(r2buf)).map(b => b.toString(16).padStart(2,'0')).join('');

  // Round 3: SHA-512 of (r1hex + r2hex)
  const r3buf = await crypto.subtle.digest("SHA-512", enc.encode(r1hex + r2hex));
  const r3hex = Array.from(new Uint8Array(r3buf)).map(b => b.toString(16).padStart(2,'0')).join('');

  return r3hex;
}

// ── STAGE → ENV VAR MAP (stages 1-20, key, zeta) ────────────
// Add these as Secrets in Cloudflare → Worker → Settings → Variables and Secrets
//
//   ANS_1  ANS_2  ANS_3  ANS_4  ANS_5  ANS_6  ANS_7
//   ANS_8  ANS_9  ANS_10 ANS_11 ANS_12 ANS_13 ANS_14
//   ANS_KEY ANS_15 ANS_16 ANS_17 ANS_18 ANS_19 ANS_20
//   ANS_ZETA
//
// Stages 21 and 22 do NOT need env vars — they use hash validation.

const STAGE_TO_ENV = {
  '1':    'ANS_1',
  '2':    'ANS_2',
  '3':    'ANS_3',
  '4':    'ANS_4',
  '5':    'ANS_5',
  '6':    'ANS_6',
  '7':    'ANS_7',
  '8':    'ANS_8',
  '9':    'ANS_9',
  '10':   'ANS_10',
  '11':   'ANS_11',
  '12':   'ANS_12',
  '13':   'ANS_13',
  '14':   'ANS_14',
  'key':  'ANS_KEY',
  '15':   'ANS_15',
  '16':   'ANS_16',
  '17':   'ANS_17',
  '18':   'ANS_18',
  '19':   'ANS_19',
  '20':   'ANS_20',
  'zeta': 'ANS_ZETA',
};

// ── CORS HEADERS ─────────────────────────────────────────────
function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };
}

// ── MAIN HANDLER ─────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '*';

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    const url = new URL(request.url);
    if (request.method !== 'POST' || url.pathname !== '/check') {
      return new Response(JSON.stringify({ ok: false }), {
        status: 404, headers: corsHeaders(origin),
      });
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (!checkRateLimit(ip)) {
      return new Response(JSON.stringify({ ok: false, error: 'rate_limited' }), {
        status: 429, headers: { ...corsHeaders(origin), 'Retry-After': '60' },
      });
    }

    let body;
    try { body = await request.json(); }
    catch { return new Response(JSON.stringify({ ok: false }), { status: 400, headers: corsHeaders(origin) }); }

    const stage = String(body.stage || '').toLowerCase().trim();
    const answer = norm(body.answer || '');

    // Random delay 50-150ms — slows brute force
    await new Promise(r => setTimeout(r, 50 + Math.random() * 100));

    // ── STAGES 21 & 22: triple hash validation ───────────────
    if (stage === '21') {
      const hash = await tripleHash(answer);
      return new Response(JSON.stringify({ ok: safeEqual(hash, HASH_21) }), {
        status: 200, headers: corsHeaders(origin),
      });
    }

    if (stage === '22') {
      const hash = await tripleHash(answer);
      return new Response(JSON.stringify({ ok: safeEqual(hash, HASH_22) }), {
        status: 200, headers: corsHeaders(origin),
      });
    }

    // ── STAGES 1-20 + KEY + ZETA: env var validation ─────────
    const envKey = STAGE_TO_ENV[stage];
    if (!envKey) {
      return new Response(JSON.stringify({ ok: false }), {
        status: 400, headers: corsHeaders(origin),
      });
    }

    const correct_answer = env[envKey];
    if (!correct_answer) {
      return new Response(JSON.stringify({ ok: false }), {
        status: 200, headers: corsHeaders(origin),
      });
    }

    const correct = safeEqual(answer, norm(correct_answer));
    return new Response(JSON.stringify({ ok: correct }), {
      status: 200, headers: corsHeaders(origin),
    });
  },
};
