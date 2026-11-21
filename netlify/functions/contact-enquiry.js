/**
 * Contact / quote enquiry — server-side spam gate before Supabase insert.
 *
 * Checks: honeypot, minimum time since form open, light heuristics, IP rate limit.
 * Cloudflare Turnstile / reCAPTCHA can be wired here when BOSS provides site+secret keys.
 *
 * Rate limit: in-memory Map on this function instance (soft limit; resets on cold start /
 * across instances). Good enough to blunt bursts; not a hard global quota.
 */
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://uloodavzquardkeecrlx.supabase.co';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_KEY ||
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InVsb29kYXZ6cXVhcmRrZWVjcmx4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI5MTc3MjMsImV4cCI6MjA4ODQ5MzcyM30.VqUNZWMKcqLolTnFDlOP874871r6AQmIEVnihdrAtwk';
// Private key (Netlify env only, never in the repo or browser). Once set, migration 006 removes
// the public insert rule so only this function can add enquiries.
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const INSERT_KEY = SUPABASE_SERVICE_KEY || SUPABASE_ANON_KEY;

const MIN_MS = 3000;
const MAX_MS = 24 * 60 * 60 * 1000;
const RATE_WINDOW_MS = 10 * 60 * 1000;
const RATE_MAX = 3;

/** @type {Map<string, number[]>} */
const hitsByIp = globalThis.__bkContactHits || (globalThis.__bkContactHits = new Map());

const THROWAYWAY = /@(mailinator|guerrillamail|tempmail|temp-mail|10minutemail|trashmail|yopmail|sharklasers|discard\.email|fakeinbox|maildrop\.cc)(\.|$)/i;

function json(status, body) {
  return {
    statusCode: status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Methods': 'POST, OPTIONS'
    },
    body: JSON.stringify(body)
  };
}

function clientIp(event) {
  const h = event.headers || {};
  const xf = h['x-nf-client-connection-ip'] || h['x-forwarded-for'] || h['client-ip'] || '';
  return String(xf).split(',')[0].trim() || 'unknown';
}

function looksGibberishName(name) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return true;
  // Multi-word names (incl. Malaysian / Chinese) pass
  if (parts.length >= 2) return false;
  const n = parts[0];
  if (n.length < 8) return false;
  if (/^[a-f0-9]{10,}$/i.test(n)) return true;
  const vowels = (n.match(/[aeiouAEIOU]/g) || []).length;
  if (n.length >= 10 && vowels / n.length < 0.15) return true;
  // Long single token of mixed case alphanumerics with digits often = bot
  if (n.length >= 12 && /\d/.test(n) && /[A-Za-z]/.test(n)) return true;
  return false;
}

function looksSpamCompany(company) {
  const c = String(company || '').trim();
  if (!c) return false;
  // Malaysian entities always pass
  if (/\bSdn\.?\s*Bhd\.?\b/i.test(c) || /\bBhd\.?\b/i.test(c) || /\bPLT\b/i.test(c) || /\bBerhad\b/i.test(c)) {
    return false;
  }
  if (!/\bLLC\b/i.test(c)) return false;
  const prefix = c.replace(/\bLLC\b\.?/i, '').trim();
  const token = prefix.split(/\s+/)[0] || '';
  // Random-looking LLC prefix (observed spam pattern)
  if (token.length >= 8 && (/^[A-Za-z0-9]+$/.test(token)) && ((token.match(/[aeiouAEIOU]/g) || []).length / token.length < 0.2 || /\d/.test(token))) {
    return true;
  }
  // Single-token name + LLC company → treat as spam when name itself looks random
  return false;
}

function isSpamPayload(d) {
  if (looksGibberishName(d.name) && looksSpamCompany(d.company)) return 'name_company';
  if (looksSpamCompany(d.company) && looksGibberishName(d.name)) return 'name_company';
  if (looksGibberishName(d.name) && !d.company) {
    // lone gibberish name without company — still suspicious if very random
    const n = String(d.name).trim();
    if (n.length >= 12 && !/\s/.test(n) && (/\d/.test(n) || /^[a-f0-9]+$/i.test(n))) return 'name';
  }
  if (d.email && THROWAYWAY.test(d.email)) return 'email';
  return null;
}

function rateLimited(ip) {
  const now = Date.now();
  let arr = hitsByIp.get(ip) || [];
  arr = arr.filter(t => now - t < RATE_WINDOW_MS);
  if (arr.length >= RATE_MAX) {
    hitsByIp.set(ip, arr);
    return true;
  }
  arr.push(now);
  hitsByIp.set(ip, arr);
  return false;
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') return json(204, {});
  if (event.httpMethod !== 'POST') return json(405, { ok: false, error: 'method_not_allowed', mode: SUPABASE_SERVICE_KEY ? 'service' : 'anon' });

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch (e) {
    return json(400, { ok: false, error: 'invalid_json' });
  }

  // Honeypot
  if (body.website || body.bot_field || body['bot-field']) {
    return json(400, { ok: false, error: 'rejected' });
  }

  // Timing since form open (client sends openedAt ms epoch)
  const openedAt = Number(body.openedAt);
  const now = Date.now();
  if (!Number.isFinite(openedAt) || openedAt <= 0) {
    return json(400, { ok: false, error: 'rejected' });
  }
  const age = now - openedAt;
  if (age < MIN_MS || age > MAX_MS) {
    return json(400, { ok: false, error: 'too_fast_or_stale' });
  }

  const d = {
    name: String(body.name || '').trim(),
    email: String(body.email || '').trim(),
    phone: String(body.phone || '').trim(),
    company: body.company == null || body.company === '' ? null : String(body.company).trim(),
    industry: body.industry == null || body.industry === '' ? null : String(body.industry).trim(),
    message: String(body.message || '').trim(),
    type: body.type === 'quote' ? 'quote' : 'quote'
  };

  if (!d.name || !d.message) return json(400, { ok: false, error: 'missing_fields' });
  if (!d.email && !d.phone) return json(400, { ok: false, error: 'missing_fields' });

  const reason = isSpamPayload(d);
  if (reason) return json(400, { ok: false, error: 'rejected' });

  const ip = clientIp(event);
  if (rateLimited(ip)) return json(429, { ok: false, error: 'rate_limited' });

  try {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/contact_submissions`, {
      method: 'POST',
      headers: {
        apikey: INSERT_KEY,
        Authorization: `Bearer ${INSERT_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal'
      },
      body: JSON.stringify([{
        name: d.name,
        email: d.email || '',
        phone: d.phone || '',
        company: d.company,
        industry: d.industry,
        message: d.message,
        type: d.type
      }])
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      console.error('supabase_insert_failed', res.status, text.slice(0, 200));
      return json(502, { ok: false, error: 'storage_failed' });
    }
    return json(200, { ok: true });
  } catch (err) {
    console.error('supabase_insert_error', err && err.message);
    return json(502, { ok: false, error: 'storage_failed' });
  }
};
