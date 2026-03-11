// ============================================================
// EPSILON WORKER — SERVER-SIDE CIPHER VALIDATION
// Answers are stored as Cloudflare Environment Variables.
// Nothing secret is in this file. Safe to be public on GitHub.
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

// ── CONSTANT-TIME COMPARE (prevents timing attacks) ──────────
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ── MAP STAGE → ENV VARIABLE NAME ────────────────────────────
// Each stage number maps to an env variable you set in Cloudflare.
// Go to: Worker → Settings → Variables and Secrets → Add each one.
//
// Variable names to add in Cloudflare dashboard:
//   ANS_1   ANS_2   ANS_3   ANS_4   ANS_5
//   ANS_6   ANS_7   ANS_8   ANS_9   ANS_10
//   ANS_11  ANS_12  ANS_13  ANS_14  ANS_KEY
//   ANS_15  ANS_16  ANS_17  ANS_18  ANS_19
//   ANS_20  ANS_ZETA ANS_21 ANS_22
//
// Set the value of each to the correct plaintext answer (lowercase).

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
  '21':   'ANS_21',
  '22':   'ANS_22',
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

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // Only POST to /check
    const url = new URL(request.url);
    if (request.method !== 'POST' || url.pathname !== '/check') {
      return new Response(JSON.stringify({ ok: false }), {
        status: 404, headers: corsHeaders(origin),
      });
    }

    // Rate limit
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (!checkRateLimit(ip)) {
      return new Response(JSON.stringify({ ok: false, error: 'rate_limited' }), {
        status: 429, headers: { ...corsHeaders(origin), 'Retry-After': '60' },
      });
    }

    // Parse body
    let body;
    try {
      body = await request.json();
    } catch {
      return new Response(JSON.stringify({ ok: false }), {
        status: 400, headers: corsHeaders(origin),
      });
    }

    const stage = String(body.stage || '').toLowerCase().trim();
    const answer = norm(body.answer || '');

    // Look up which env variable holds this stage's answer
    const envKey = STAGE_TO_ENV[stage];
    if (!envKey) {
      return new Response(JSON.stringify({ ok: false }), {
        status: 400, headers: corsHeaders(origin),
      });
    }

    // Read the answer from Cloudflare env (never from code)
    const correct_answer = env[envKey];

    // If the env variable hasn't been set yet, block silently
    if (!correct_answer) {
      return new Response(JSON.stringify({ ok: false }), {
        status: 200, headers: corsHeaders(origin),
      });
    }

    // Constant-time compare
    const correct = safeEqual(answer, norm(correct_answer));

    // Random delay 50-150ms to slow brute force
    await new Promise(r => setTimeout(r, 50 + Math.random() * 100));

    return new Response(JSON.stringify({ ok: correct }), {
      status: 200, headers: corsHeaders(origin),
    });
  },
};
