// Esta función es el único camino permitido para guardar una evaluación.
// El navegador ya no habla directo con Supabase para insertar: primero
// pasa por aquí, donde se verifica con Cloudflare que quien envía es una
// persona real antes de aceptar el dato. La clave secreta de Turnstile
// vive solo en el servidor (variable de entorno de Vercel), nunca en el HTML.

const SB_URL = 'https://oiijljmnpeglwrfcamlq.supabase.co';
const SB_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9paWpsam1ucGVnbHdyZmNhbWxxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODEzNzQ3NTAsImV4cCI6MjA5Njk1MDc1MH0.o3cTyedBuYbAXiUR1Q3uZts_UK9V-9Quob4SuGCIYVM';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'method_not_allowed' });
  }

  const { token, place, tipo, subcat, provincia, scores } = req.body || {};

  if (!token) {
    return res.status(400).json({ ok: false, error: 'missing_token' });
  }
  if (!place || typeof place !== 'string' || !scores) {
    return res.status(400).json({ ok: false, error: 'missing_data' });
  }

  // 1. Verificar con Cloudflare que el token del formulario es real y no expiró.
  try {
    const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: process.env.TURNSTILE_SECRET_KEY,
        response: token,
        remoteip: (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
      })
    });
    const verifyData = await verifyRes.json();
    if (!verifyData.success) {
      return res.status(403).json({ ok: false, error: 'captcha_failed' });
    }
  } catch (e) {
    return res.status(502).json({ ok: false, error: 'captcha_verify_error' });
  }

  // 2. Solo si el CAPTCHA pasó, se guarda de verdad en Supabase.
  try {
    const r = await fetch(SB_URL + '/rest/v1/ratings', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': SB_KEY,
        'Authorization': 'Bearer ' + SB_KEY,
        'Prefer': 'return=minimal'
      },
      body: JSON.stringify({
        place: place, tipo: tipo || '', subcat: subcat || '', provincia: provincia || '',
        atencion: scores.atencion, limpieza: scores.limpieza, eficiencia: scores.eficiencia,
        accesibilidad: scores.accesibilidad, seguridad: scores.seguridad, ambiente: scores.ambiente
      })
    });
    if (!r.ok) {
      return res.status(502).json({ ok: false, error: 'insert_failed' });
    }
    return res.status(200).json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
}
