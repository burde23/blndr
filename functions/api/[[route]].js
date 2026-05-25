// ═══════════════════════════════════════════════════════════════════
//  BLNDR. — Cloudflare Worker + D1
//  Maneja: auth, users, events
// ═══════════════════════════════════════════════════════════════════

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

// ── Utilidades ─────────────────────────────────────────────────────

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// Token simple: base64(userId:timestamp:secret)
async function makeToken(userId, secret) {
  const raw = `${userId}:${Date.now()}`;
  const enc = btoa(raw + ':' + secret.slice(0, 8));
  return enc;
}

async function verifyToken(token, env) {
  try {
    const dec = atob(token);
    const parts = dec.split(':');
    const userId = parseInt(parts[0]);
    if (isNaN(userId)) return null;
    // Verificamos que el usuario exista
    const row = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(userId).first();
    return row ? userId : null;
  } catch {
    return null;
  }
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + 'blndr_salt_2025');
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function requireAuth(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return null;
  return await verifyToken(token, env);
}

// ── Router principal ───────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    // ── Servir el frontend (index.html) ────────────────────────────
    if (method === 'GET' && (path === '/' || path === '/index.html')) {
      const asset = await env.ASSETS.fetch(request);
      return asset;
    }

    // ── API Routes ─────────────────────────────────────────────────

    // POST /api/register
    if (method === 'POST' && path === '/api/register') {
      return handleRegister(request, env);
    }

    // POST /api/login
    if (method === 'POST' && path === '/api/login') {
      return handleLogin(request, env);
    }

    // GET /api/me
    if (method === 'GET' && path === '/api/me') {
      return handleGetMe(request, env);
    }

    // PUT /api/me
    if (method === 'PUT' && path === '/api/me') {
      return handleUpdateMe(request, env);
    }

    // GET /api/users
    if (method === 'GET' && path === '/api/users') {
      return handleGetUsers(request, env);
    }

    // GET /api/events
    if (method === 'GET' && path === '/api/events') {
      return handleGetEvents(request, env);
    }

    // POST /api/events
    if (method === 'POST' && path === '/api/events') {
      return handleCreateEvent(request, env);
    }

    // DELETE /api/events/:id
    if (method === 'DELETE' && path.startsWith('/api/events/')) {
      const id = parseInt(path.split('/')[3]);
      return handleDeleteEvent(request, env, id);
    }

    // Fallback: assets estáticos (Cloudflare Pages Assets)
    try {
      return await env.ASSETS.fetch(request);
    } catch {
      return err('Not found', 404);
    }
  },
};

// ── Handlers ───────────────────────────────────────────────────────

async function handleRegister(request, env) {
  let body;
  try { body = await request.json(); } catch { return err('JSON inválido'); }

  const { name, username, password, color, avatar } = body;
  if (!name || !username || !password) return err('Faltan campos obligatorios');
  if (username.length < 3) return err('El usuario debe tener al menos 3 caracteres');
  if (password.length < 6) return err('La contraseña debe tener al menos 6 caracteres');

  const clean_user = username.toLowerCase().replace(/[^a-z0-9_]/g, '');
  if (clean_user.length < 3) return err('Usuario inválido (solo letras, números y _)');

  // Verificar si ya existe
  const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(clean_user).first();
  if (existing) return err('Ese usuario ya está en uso');

  const hashed = await hashPassword(password);
  const userColor = color || '#c8ff00';
  const userAvatar = avatar || '🦋';

  const result = await env.DB.prepare(
    'INSERT INTO users (name, username, password_hash, color, avatar) VALUES (?, ?, ?, ?, ?) RETURNING id'
  ).bind(name.trim(), clean_user, hashed, userColor, userAvatar).first();

  const userId = result.id;
  const token = await makeToken(userId, env.JWT_SECRET || 'blndr2025secret');

  return json({
    token,
    user: { id: userId, name: name.trim(), username: clean_user, color: userColor, avatar: userAvatar },
  }, 201);
}

async function handleLogin(request, env) {
  let body;
  try { body = await request.json(); } catch { return err('JSON inválido'); }

  const { username, password } = body;
  if (!username || !password) return err('Faltan campos');

  const clean_user = username.toLowerCase().trim();
  const row = await env.DB.prepare(
    'SELECT id, name, username, color, avatar, password_hash FROM users WHERE username = ?'
  ).bind(clean_user).first();

  if (!row) return err('Usuario o contraseña incorrectos', 401);

  const hashed = await hashPassword(password);
  if (hashed !== row.password_hash) return err('Usuario o contraseña incorrectos', 401);

  const token = await makeToken(row.id, env.JWT_SECRET || 'blndr2025secret');

  return json({
    token,
    user: { id: row.id, name: row.name, username: row.username, color: row.color, avatar: row.avatar },
  });
}

async function handleGetMe(request, env) {
  const userId = await requireAuth(request, env);
  if (!userId) return err('No autenticado', 401);

  const row = await env.DB.prepare(
    'SELECT id, name, username, color, avatar FROM users WHERE id = ?'
  ).bind(userId).first();

  if (!row) return err('Usuario no encontrado', 404);
  return json({ user: row });
}

async function handleUpdateMe(request, env) {
  const userId = await requireAuth(request, env);
  if (!userId) return err('No autenticado', 401);

  let body;
  try { body = await request.json(); } catch { return err('JSON inválido'); }

  const { color, avatar, name } = body;
  const updates = [];
  const values = [];

  if (color) { updates.push('color = ?'); values.push(color); }
  if (avatar) { updates.push('avatar = ?'); values.push(avatar); }
  if (name) { updates.push('name = ?'); values.push(name.trim()); }

  if (updates.length === 0) return err('Nada para actualizar');

  values.push(userId);
  await env.DB.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();

  const row = await env.DB.prepare(
    'SELECT id, name, username, color, avatar FROM users WHERE id = ?'
  ).bind(userId).first();

  return json({ user: row });
}

async function handleGetUsers(request, env) {
  const userId = await requireAuth(request, env);
  if (!userId) return err('No autenticado', 401);

  const { results } = await env.DB.prepare(
    'SELECT id, name, username, color, avatar FROM users ORDER BY name'
  ).all();

  return json({ users: results });
}

async function handleGetEvents(request, env) {
  const userId = await requireAuth(request, env);
  if (!userId) return err('No autenticado', 401);

  const { results } = await env.DB.prepare(
    'SELECT * FROM events ORDER BY created_at DESC'
  ).all();

  // Parsear recurring_days de JSON string a array
  const events = results.map(ev => ({
    ...ev,
    recurring_days: (() => {
      try { return JSON.parse(ev.recurring_days || '[]'); } catch { return []; }
    })(),
  }));

  return json({ events });
}

async function handleCreateEvent(request, env) {
  const userId = await requireAuth(request, env);
  if (!userId) return err('No autenticado', 401);

  let body;
  try { body = await request.json(); } catch { return err('JSON inválido'); }

  const {
    type = 'otro',
    description,
    date_start = null,
    date_end = null,
    time_start = null,
    time_end = null,
    recurring_days = [],
    location = null,
    lat = null,
    lng = null,
  } = body;

  if (!description) return err('La descripción es obligatoria');

  const rdJson = JSON.stringify(Array.isArray(recurring_days) ? recurring_days : []);

  const result = await env.DB.prepare(
    `INSERT INTO events
      (user_id, type, description, date_start, date_end, time_start, time_end, recurring_days, location, lat, lng)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     RETURNING id`
  ).bind(userId, type, description.trim(), date_start, date_end, time_start, time_end, rdJson, location, lat, lng).first();

  return json({ event: { id: result.id, user_id: userId, ...body, recurring_days: Array.isArray(recurring_days) ? recurring_days : [] } }, 201);
}

async function handleDeleteEvent(request, env, id) {
  const userId = await requireAuth(request, env);
  if (!userId) return err('No autenticado', 401);
  if (isNaN(id)) return err('ID inválido');

  const ev = await env.DB.prepare('SELECT user_id FROM events WHERE id = ?').bind(id).first();
  if (!ev) return err('Evento no encontrado', 404);
  if (ev.user_id !== userId) return err('No podés borrar eventos ajenos', 403);

  await env.DB.prepare('DELETE FROM events WHERE id = ?').bind(id).run();
  return json({ deleted: true });
}
