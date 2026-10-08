// Único camino permitido para guardar una evaluación.
// El navegador NO habla directo con Supabase para insertar: pasa por aquí.
// Aquí se hace, en este orden:
//   1. Validar los datos (tipos, rangos y largos).
//   2. Verificar con Cloudflare (Turnstile) que quien envía es una persona.
//   3. Aplicar un límite por huella anónima (hash de la IP) y por lugar/día.
//   4. Guardar con una clave privada que vive SOLO en Vercel (variables de entorno).
//
// Variables de entorno en Vercel:
//   TURNSTILE_SECRET_KEY         (ya existe)
//   SUPABASE_SERVICE_ROLE_KEY    (clave privada de Supabase)

const crypto = require('crypto');

const SB_URL = 'https://oiijljmnpeglwrfcamlq.supabase.co';
// Clave pública (anon). Solo se usa si falta la clave privada (transición).
const SB_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9paWpsam1ucGVnbHdyZmNhbWxxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODEzNzQ3NTAsImV4cCI6MjA5Njk1MDc1MH0.o3cTyedBuYbAXiUR1Q3uZts_UK9V-9Quob4SuGCIYVM';

// Dominios desde los que se acepta el formulario (Turnstile devuelve el hostname).
const ALLOWED_HOSTNAMES = ['promundi.tech', 'www.promundi.tech', 'promundi.vercel.app'];

// Límites. Ajusta estos números sin tocar el resto del código.
const MAX_PER_PLACE_PER_DAY = 2;   // evaluaciones del mismo lugar por huella en 24 h
const MAX_PER_DAY = 20;            // evaluaciones totales por huella en 24 h
const WINDOW_MS = 24 * 60 * 60 * 1000;

const SCORE_KEYS = ['atencion', 'limpieza', 'eficiencia', 'accesibilidad', 'seguridad', 'ambiente'];

function fail(res, status, error) {
  return res.status(status).json({ ok: false, error: error });
}

function cleanText(v, max) {
  if (typeof v !== 'string') return null;
  const s = v.replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').trim();
  if (s.length > max) return null;
  return s;
}

function normKey(s) {
  return s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/\s+/g, ' ').trim();
}

function sbHeaders(key, extra) {
  const h = { 'Content-Type': 'application/json', 'apikey': key };
  // Las claves antiguas (JWT, empiezan con eyJ) van también como Bearer.
  // Las claves nuevas (sb_secret_...) solo van en 'apikey'.
  if (key.indexOf('eyJ') === 0) h['Authorization'] = 'Bearer ' + key;
  return Object.assign(h, extra || {});
}

function clientIp(req) {
  const h = req.headers || {};
  const real = (h['x-real-ip'] || '').trim();
  if (real) return real;
  return String(h['x-forwarded-for'] || '').split(',')[0].trim();
}

async function countRecent(key, filter) {
  const since = new Date(Date.now() - WINDOW_MS).toISOString();
  const url = SB_URL + '/rest/v1/ratings?select=id&' + filter + '&created_at=gte.' + encodeURIComponent(since);
  const r = await fetch(url, { method: 'HEAD', headers: sbHeaders(key, { 'Prefer': 'count=exact' }) });
  if (!r.ok) throw new Error('count_failed');
  const range = r.headers.get('content-range') || '';
  const total = parseInt(range.split('/')[1], 10);
  if (isNaN(total)) throw new Error('count_unreadable');
  return total;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return fail(res, 405, 'method_not_allowed');

  const body = req.body || {};
  const token = typeof body.token === 'string' ? body.token : '';
  if (!token || token.length > 4096) return fail(res, 400, 'missing_token');

  // ── 1. Validación ──
  const place = cleanText(body.place, 80);
  const tipo = cleanText(body.tipo == null ? '' : body.tipo, 40);
  const subcat = cleanText(body.subcat == null ? '' : body.subcat, 80);
  const provincia = cleanText(body.provincia == null ? '' : body.provincia, 40);
  if (!place || place.length < 2) return fail(res, 400, 'invalid_place');
  if (tipo === null || subcat === null || provincia === null) return fail(res, 400, 'invalid_fields');

  const scores = body.scores;
  if (!scores || typeof scores !== 'object') return fail(res, 400, 'missing_scores');
  const row = {};
  for (let i = 0; i < SCORE_KEYS.length; i++) {
    const v = scores[SCORE_KEYS[i]];
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 1 || v > 5) return fail(res, 400, 'invalid_scores');
    row[SCORE_KEYS[i]] = v;
  }

  const ip = clientIp(req);

  // ── 2. Turnstile ──
  if (!process.env.TURNSTILE_SECRET_KEY) return fail(res, 500, 'server_misconfigured');
  try {
    const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: process.env.TURNSTILE_SECRET_KEY, response: token, remoteip: ip })
    });
    const v = await verifyRes.json();
    if (!v.success) return fail(res, 403, 'captcha_failed');
    if (v.hostname && ALLOWED_HOSTNAMES.indexOf(v.hostname) === -1) return fail(res, 403, 'captcha_wrong_host');
  } catch (e) {
    return fail(res, 502, 'captcha_verify_error');
  }

  // ── 3. Límite por huella anónima ──
  // La IP nunca se guarda: se guarda un HMAC irreversible (con la clave secreta como llave).
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY || '';
  const key = serviceKey || SB_ANON_KEY;
  if (!serviceKey) console.warn('[submit] Falta SUPABASE_SERVICE_ROLE_KEY: usando clave anon (modo transición).');

  const placeKey = normKey(place);
  const ipHash = ip
    ? crypto.createHmac('sha256', process.env.TURNSTILE_SECRET_KEY).update(ip).digest('hex').slice(0, 32)
    : null;

  if (ipHash && serviceKey) {
    try {
      const perPlace = await countRecent(key, 'ip_hash=eq.' + ipHash + '&place_key=eq.' + encodeURIComponent(placeKey));
      if (perPlace >= MAX_PER_PLACE_PER_DAY) return fail(res, 429, 'rate_limited_place');
      const perDay = await countRecent(key, 'ip_hash=eq.' + ipHash);
      if (perDay >= MAX_PER_DAY) return fail(res, 429, 'rate_limited_day');
    } catch (e) {
      return fail(res, 503, 'limit_check_failed');
    }
  }

  // ── 4. Guardar ──
  try {
    const r = await fetch(SB_URL + '/rest/v1/ratings', {
      method: 'POST',
      headers: sbHeaders(key, { 'Prefer': 'return=minimal' }),
      body: JSON.stringify(Object.assign({
        place: place, tipo: tipo, subcat: subcat, provincia: provincia,
        place_key: placeKey, ip_hash: ipHash
      }, row))
    });
    if (!r.ok) return fail(res, 502, 'insert_failed');
    return res.status(200).json({ ok: true });
  } catch (e) {
    return fail(res, 500, 'server_error');
  }
};
