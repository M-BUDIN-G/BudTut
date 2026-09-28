'use strict';
/**
 * BudTut demo backend — registration, login, job posting.
 *   npm install && npm start   ->   http://localhost:3000
 *
 * Storage: a single JSON file (data/db.json). Fine for testing; swap for Postgres later.
 * Only dependency: express. Passwords use crypto.scrypt, sessions are random bearer tokens.
 */
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');

const PORT = process.env.PORT || 3000;
// On a host with an ephemeral filesystem (most PaaS "app" containers) this MUST point at a
// mounted persistent disk, e.g. DATA_DIR=/data — otherwise every deploy/restart wipes the DB.
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const SESSION_DAYS = 30;
const CANONICAL_HOST = process.env.CANONICAL_HOST || ''; // e.g. budtut.eu — redirects other hosts (www., etc.) to this one
const APP_BASE_URL = process.env.APP_BASE_URL || (CANONICAL_HOST ? `https://${CANONICAL_HOST}` : `http://localhost:${PORT}`);
// SMTP for verification e-mails. Any account works (a Gmail address with an "app password" is fine).
// Without these set, e-mails are just logged to the console — the flow still works for local testing.
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const MAIL_FROM = process.env.MAIL_FROM || SMTP_USER;
// Free public NIP->CEIDG check (JDG) needs a "Hurtownia danych" JWT from dane.biznes.gov.pl
// (registration is free but requires logging in with a Profil Zaufany). Until this is set, JDG
// lookups fall back to a clearly-marked demo result so the registration form stays usable.
const CEIDG_JWT = process.env.CEIDG_JWT || '';
// Google Sign-In (free) -- create an OAuth Client ID ("Web application") at
// https://console.cloud.google.com/apis/credentials, add this site's origin(s) under
// "Authorized JavaScript origins", then set GOOGLE_CLIENT_ID. Until set, the Google button tells
// the user the feature isn't configured yet instead of failing silently.
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;
// reCAPTCHA v2 checkbox (free) -- register the site at https://www.google.com/recaptcha/admin to
// get a site key (public, goes in the page) and a secret key (private, server-only). Until
// RECAPTCHA_SECRET_KEY is set, registration simply skips the check (keeps local dev usable).
const RECAPTCHA_SITE_KEY = process.env.RECAPTCHA_SITE_KEY || '';
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY || '';

// ---------- Tiny JSON database ----------
fs.mkdirSync(DATA_DIR, { recursive: true });
let db = { users: [], sessions: [], jobs: [], reviews: [], services: [], verifications: [], contacts: [], reports: [], deletionRequests: [] };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))); } catch (e) { /* first run */ }
db.reviews = (db.reviews || []).filter((r) => r.targetId && r.authorId); // drop early demo-format reviews
db.services = db.services || [];
db.verifications = db.verifications || [];
db.contacts = db.contacts || [];
db.reports = db.reports || [];
db.deletionRequests = db.deletionRequests || [];
function save() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}
const uid = () => crypto.randomBytes(8).toString('hex');

// ---------- Domain constants (keep in sync with the frontend) ----------
const CATEGORIES = ['drywall', 'electrical', 'painting', 'tiling', 'plumbing', 'renovation', 'flooring', 'roofing'];
const CITIES = ['gdansk', 'gdynia', 'sopot', 'warszawa', 'krakow'];
const POSITIONS = ['president', 'member', 'proxy', 'other'];
const TYPES = ['person', 'jdg', 'company'];
const GENDERS = ['male', 'female'];

// ---------- Helpers ----------
const clean = (v, max) => String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);

// ---------- Date of birth (YYYY-MM-DD, must be a real date, 18+) ----------
function birthCheck(v) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(v || ''));
  if (!m) return v ? 'birth_invalid' : 'required';
  const y = +m[1], mo = +m[2], d = +m[3], dt = new Date(Date.UTC(y, mo - 1, d));
  if (y < 1900 || dt.getUTCFullYear() !== y || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) return 'birth_invalid';
  if (Date.now() < Date.UTC(y + 18, mo - 1, d)) return 'underage';
  return null;
}
const emailOk = (s) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s) && s.length <= 254;

function nipValid(n) {
  if (!/^\d{10}$/.test(n)) return false;
  const w = [6, 5, 7, 2, 3, 4, 5, 6, 7];
  let s = 0; for (let i = 0; i < 9; i++) s += w[i] * Number(n[i]);
  return s % 11 === Number(n[9]);
}

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 64);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}
function verifyPassword(pw, stored) {
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(pw, Buffer.from(salt, 'hex'), 64);
  return crypto.timingSafeEqual(test, Buffer.from(hash, 'hex'));
}
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ---------- Email (verification links etc.) ----------
const mailer = SMTP_HOST && SMTP_USER && SMTP_PASS
  ? nodemailer.createTransport({ host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_PORT === 465, auth: { user: SMTP_USER, pass: SMTP_PASS } })
  : null;
async function sendMail(to, subject, text, html) {
  if (!mailer) { console.log(`[mail:dev] to=${to} subject=${subject}\n${text}`); return; }
  try { await mailer.sendMail({ from: MAIL_FROM, to, subject, text, html }); }
  catch (e) { console.error('sendMail failed:', e.message); }
}

// ---------- reCAPTCHA v2 ----------
async function verifyCaptcha(token, ip) {
  if (!RECAPTCHA_SECRET_KEY) return true; // not configured -> don't block local/dev usage
  if (!token) return false;
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    const body = new URLSearchParams({ secret: RECAPTCHA_SECRET_KEY, response: String(token), remoteip: ip || '' });
    const res = await fetch('https://www.google.com/recaptcha/api/siteverify', { method: 'POST', body, signal: ctrl.signal });
    clearTimeout(t);
    const data = await res.json();
    return !!(data && data.success);
  } catch (e) {
    console.error('verifyCaptcha failed:', e.message);
    return false; // fail closed once configured: a broken check should never let spam through
  }
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.sessions = db.sessions.filter((s) => s.exp > Date.now());
  db.sessions.push({ h: sha(token), userId, exp: Date.now() + SESSION_DAYS * 864e5 });
  return token;
}
const displayName = (u) => u.deleted ? '' : (u.type === 'company' && u.business && u.business.name ? u.business.name : `${u.first} ${u.last}`.trim());
const avatarUrl = (u) => (u.avatar ? '/api/users/' + u.id + '/avatar?v=' + u.avatarV : null);
const publicUser = (u) => ({
  avatarUrl: avatarUrl(u), id: u.id, type: u.type, gender: u.gender || null, birth: u.birth || null, first: u.first, last: u.last, email: u.email, phone: u.phone, name: displayName(u),
  position: u.position || null, business: u.business || null, verified: !!u.verified, emailVerified: !!u.emailVerified, hasPassword: !!u.passHash, createdAt: u.createdAt,
});

/**
 * Company registry lookup.
 *   sp. z o.o. by KRS number -> REAL data, free, no API key: the Ministry of Justice's own
 *   public KRS API (the same data https://wyszukiwarka-krs.ms.gov.pl shows).
 *   JDG by NIP / company by NIP (not KRS) -> a real check needs the CEIDG "Hurtownia danych"
 *   API (free, but registration requires logging in with a Profil Zaufany at
 *   dane.biznes.gov.pl -> set CEIDG_JWT once you have it). Until then this clearly-marked demo
 *   lookup keeps the registration form usable.
 */
const KRS_API = 'https://api-krs.ms.gov.pl/api/krs/OdpisAktualny';

async function fetchJson(url, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { Accept: 'application/json' } });
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    console.error('fetchJson failed:', url, e.message);
    return null;
  } finally {
    clearTimeout(t);
  }
}

function demoLookupCompany({ type, number, first = '', last = '' }) {
  const nip = String(number || '').replace(/\D/g, '');
  const regon = String(Number(nip.slice(0, 9)) % 1e9).padStart(9, '0');
  if (type === 'jdg') {
    const owner = (first || last ? `${first} ${last}`.trim() : 'Jan Kowalski').toUpperCase();
    return { name: `${owner} USŁUGI REMONTOWE`, nip, regon, city: 'Gdańsk', active: true, source: 'demo' };
  }
  return {
    name: 'DEMO BUDOWLANA SP. Z O.O.', nip, krs: '0000' + nip.slice(0, 6), regon,
    legal: 'legal_sp_zoo', address: 'ul. Przykładowa 10, 80-000 Gdańsk', city: 'Gdańsk', active: true, source: 'demo',
  };
}

// Only legal form this platform has a translated label for (see `legal_sp_zoo` in the frontend).
function mapLegalForm(formaPrawna) {
  const f = String(formaPrawna || '').toUpperCase();
  return f === 'SPÓŁKA Z OGRANICZONĄ ODPOWIEDZIALNOŚCIĄ' ? 'legal_sp_zoo' : null;
}

async function lookupKrs(krsNumber, { first = '', last = '' } = {}) {
  const data = await fetchJson(`${KRS_API}/${encodeURIComponent(krsNumber)}?rejestr=P&format=json`);
  const dzial1 = data && data.odpis && data.odpis.dane && data.odpis.dane.dzial1;
  const podmiot = dzial1 && dzial1.danePodmiotu;
  if (!podmiot || !podmiot.nazwa) return null; // not found / bad number

  const legal = mapLegalForm(podmiot.formaPrawna);
  if (!legal) return null; // legal form we don't support yet (only sp. z o.o.)

  // Being wound up / bankrupt / struck off shows up as populated dzial6 sections.
  const dzial6 = data.odpis.dane.dzial6 || {};
  const beingWoundUp = !!(dzial6.likwidacja || dzial6.postepowanieUpadlosciowe
    || (Array.isArray(dzial6.rozwiazanieUniewaznienie) && dzial6.rozwiazanieUniewaznienie.length));
  if (beingWoundUp) return null; // the frontend has no "inactive" state yet, so treat as not usable

  const a = (dzial1.siedzibaIAdres && dzial1.siedzibaIAdres.adres) || {};
  const street = [a.ulica, a.nrDomu].filter(Boolean).join(' ') + (a.nrLokalu ? `/${a.nrLokalu}` : '');
  const address = [street, [a.kodPocztowy, a.miejscowosc].filter(Boolean).join(' ')].filter(Boolean).join(', ');

  // Cross-check the declared representative's initials against the management board ("zarząd").
  // The public API only exposes first-letter-masked names (e.g. "M******"), so this is a light
  // signal for the admin reviewing the request, never a substitute for real identity checks.
  const board = (data.odpis.dane.dzial2 && data.odpis.dane.dzial2.reprezentacja && data.odpis.dane.dzial2.reprezentacja.sklad) || [];
  const fi = (first || '').trim().charAt(0).toUpperCase();
  const li = (last || '').trim().charAt(0).toUpperCase();
  const repMatch = !!(fi && li && board.some((m) => {
    const mLast = m.nazwisko && m.nazwisko.nazwiskoICzlon && m.nazwisko.nazwiskoICzlon.charAt(0);
    const mFirst = m.imiona && m.imiona.imie && m.imiona.imie.charAt(0);
    return mLast === li && mFirst === fi;
  }));

  return {
    name: podmiot.nazwa,
    nip: (podmiot.identyfikatory && podmiot.identyfikatory.nip) || '',
    krs: krsNumber,
    regon: (podmiot.identyfikatory && podmiot.identyfikatory.regon) || '',
    legal, address, city: a.miejscowosc || '', active: true, repMatch, source: 'krs',
  };
}

async function lookupCompany({ type, number, first = '', last = '' }) {
  const digits = String(number || '').replace(/\D/g, '');
  let kind = null;
  if (digits.length === 10) {
    if (type === 'company' && digits.startsWith('000')) kind = 'krs';
    else if (nipValid(digits)) kind = 'nip';
  }
  if (!kind) return null;

  if (kind === 'krs') {
    return await lookupKrs(digits, { first, last }); // no demo fallback: an unknown KRS should just fail
  }
  // kind === 'nip': real CEIDG (jdg) / NIP->KRS resolution (company) are TODO, see comment above.
  return demoLookupCompany({ type, number: digits, first, last });
}

// ---------- Google Sign-In ----------
// Verifies the ID token from Google Identity Services (the "Sign in with Google" JS button) and
// returns the verified profile, or null if it's missing / invalid / expired / wrong audience.
async function verifyGoogleToken(credential) {
  if (!googleClient || !credential) return null;
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const p = ticket.getPayload();
    if (!p || !p.email || !p.email_verified) return null;
    return {
      sub: p.sub, email: String(p.email).toLowerCase(),
      first: p.given_name || (p.name || '').split(' ')[0] || 'User',
      last: p.family_name || (p.name || '').split(' ').slice(1).join(' ') || '',
    };
  } catch (e) {
    console.error('verifyGoogleToken failed:', e.message);
    return null;
  }
}

// ---------- Rate limiting (in memory) ----------
const hits = new Map();
function limit(name, max, windowMs) {
  return (req, res, next) => {
    const key = name + ':' + req.ip, now = Date.now();
    const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
    if (arr.length >= max) return res.status(429).json({ error: 'rate_limited' });
    arr.push(now); hits.set(key, arr); next();
  };
}

// ---------- App ----------
const app = express();
app.disable('x-powered-by');
// Trust the first hop's X-Forwarded-* headers (Render/most PaaS sit exactly one reverse proxy
// away). This is what makes req.ip — and therefore the per-IP rate limiter above — see the real
// client IP instead of the proxy's, and is required for req.secure to work behind TLS-terminating
// proxies. Harmless in local dev (no proxy → falls back to the raw socket address).
app.set('trust proxy', 1);
const jsonSmall = express.json({ limit: '50kb' }), jsonAvatar = express.json({ limit: '450kb' });
app.use((req, res, next) => (req.path === '/api/me/avatar' ? jsonAvatar : jsonSmall)(req, res, next));

// CORS so the page also works when opened straight from a file (file://)
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Health check for the hosting platform (deploy/rollout probes) — before any redirects/auth.
app.get('/healthz', (req, res) => res.status(200).json({ ok: true }));

// Canonical-host + HTTPS redirect (e.g. www.budtut.eu -> budtut.eu, and http -> https).
// Only active once CANONICAL_HOST is set, so local dev / preview URLs are unaffected.
if (CANONICAL_HOST) {
  app.use((req, res, next) => {
    const host = (req.headers.host || '').split(':')[0];
    if (host !== CANONICAL_HOST || (!req.secure && req.get('x-forwarded-proto') !== 'https' && process.env.NODE_ENV === 'production')) {
      return res.redirect(301, `https://${CANONICAL_HOST}${req.originalUrl}`);
    }
    next();
  });
}

function auth(req, res, next) {
  const m = /^Bearer (\w{64})$/.exec(req.get('Authorization') || '');
  if (!m) return res.status(401).json({ error: 'unauthorized' });
  const s = db.sessions.find((x) => x.h === sha(m[1]) && x.exp > Date.now());
  const user = s && db.users.find((u) => u.id === s.userId);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  req.user = user; req.tokenHash = s.h; next();
}

// ----- Auth -----
app.post('/api/auth/register', limit('reg', 20, 60 * 60e3), async (req, res) => {
  const b = req.body || {};
  const errors = {};
  const type = TYPES.includes(b.type) ? b.type : null;
  if (!type) return res.status(400).json({ error: 'invalid', errors: { type: 'required' } });
  const captchaOk = await verifyCaptcha(b.captcha, req.ip);

  const first = clean(b.first, 60), last = clean(b.last, 80), email = clean(b.email, 254).toLowerCase();
  const phone = clean(b.phone, 30), password = String(b.password ?? '');
  if (!first) errors.first = 'required';
  if (!last) errors.last = 'required';
  if (!email) errors.email = 'required'; else if (!emailOk(email)) errors.email = 'email_invalid';
  const digits = phone.replace(/\D/g, '');
  if (!phone) errors.phone = 'required';
  else if (!/^\+?[\d\s()-]+$/.test(phone) || digits.length < 9 || digits.length > 15) errors.phone = 'phone_invalid';
  if (!password) errors.password = 'required'; else if (password.length < 8 || password.length > 200) errors.password = 'password_short';
  if (b.terms !== true) errors.terms = 'terms';

  const birthErr = birthCheck(b.birth); if (birthErr) errors.birth = birthErr;
  let gender = null;
  if (type !== 'company') { if (GENDERS.includes(b.gender)) gender = b.gender; else errors.gender = 'required'; }
  let business = null, position = null;
  if (type !== 'person') {
    business = await lookupCompany({ type, number: b.business && b.business.number, first, last });
    if (!business) errors.business = 'business_invalid';
    else if (!b.business.confirmed) errors.business = 'business_unconfirmed';
  }
  if (type === 'company') {
    if (!POSITIONS.includes(b.position)) errors.position = 'required'; else position = b.position;
    if (b.authority !== true) errors.authority = 'authority';
  }
  if (!captchaOk) errors.captcha = 'captcha_invalid';
  if (Object.keys(errors).length) return res.status(400).json({ error: 'invalid', errors });
  if (db.users.some((u) => u.email === email)) return res.status(409).json({ error: 'invalid', errors: { email: 'email_taken' } });

  const emailVerifyToken = crypto.randomBytes(24).toString('hex');
  const user = {
    id: uid(), type, gender, birth: b.birth, first, last, email, phone, position, business,
    passHash: hashPassword(password), verified: false, createdAt: new Date().toISOString(),
    emailVerified: false, emailVerifyTokenHash: sha(emailVerifyToken), emailVerifyExpires: Date.now() + 24 * 3600e3,
  };
  db.users.push(user);
  const token = createSession(user.id);
  save();
  const verifyUrl = `${APP_BASE_URL}/?verifyEmail=${emailVerifyToken}`;
  sendMail(user.email, 'Potwierdź swój adres e-mail – BudTut',
    `Cześć ${first},\n\nPotwierdź swój adres e-mail, klikając w link:\n${verifyUrl}\n\nLink jest ważny 24 godziny.\n\n— BudTut`,
    `<p>Cześć ${escapeHtml(first)},</p><p>Potwierdź swój adres e-mail, klikając w link poniżej:</p><p><a href="${verifyUrl}">${verifyUrl}</a></p><p>Link jest ważny 24 godziny.</p><p>— BudTut</p>`);
  res.status(201).json({ token, user: publicUser(user) });
});

app.post('/api/auth/login', limit('login', 15, 10 * 60e3), (req, res) => {
  const email = clean(req.body && req.body.email, 254).toLowerCase();
  const password = String((req.body && req.body.password) ?? '');
  const user = db.users.find((u) => u.email === email && !u.deleted);
  // same work + same answer for unknown e-mail and wrong password
  const ok = user && user.passHash ? verifyPassword(password, user.passHash) : (crypto.scryptSync(password, 'x'.repeat(16), 64), false);
  if (!ok) return res.status(401).json({ error: 'bad_credentials' });
  const token = createSession(user.id);
  save();
  res.json({ token, user: publicUser(user) });
});

app.get('/api/auth/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.post('/api/auth/logout', auth, (req, res) => {
  db.sessions = db.sessions.filter((s) => s.h !== req.tokenHash);
  save(); res.json({ ok: true });
});

// ----- Email verification -----
app.get('/api/auth/verify-email', limit('verifyemail', 30, 60 * 60e3), (req, res) => {
  const token = String(req.query.token || '');
  if (!/^[0-9a-f]{48}$/.test(token)) return res.status(400).json({ error: 'invalid' });
  const h = sha(token);
  const user = db.users.find((u) => u.emailVerifyTokenHash === h && !u.deleted);
  if (!user || !user.emailVerifyExpires || user.emailVerifyExpires < Date.now()) return res.status(400).json({ error: 'invalid_or_expired' });
  user.emailVerified = true;
  delete user.emailVerifyTokenHash; delete user.emailVerifyExpires;
  save();
  res.json({ ok: true });
});
app.post('/api/auth/resend-verification', auth, limit('resendverif', 5, 60 * 60e3), (req, res) => {
  if (req.user.emailVerified) return res.status(409).json({ error: 'already_verified' });
  const token = crypto.randomBytes(24).toString('hex');
  req.user.emailVerifyTokenHash = sha(token); req.user.emailVerifyExpires = Date.now() + 24 * 3600e3;
  save();
  const verifyUrl = `${APP_BASE_URL}/?verifyEmail=${token}`;
  sendMail(req.user.email, 'Potwierdź swój adres e-mail – BudTut',
    `Cześć ${req.user.first},\n\nPotwierdź swój adres e-mail:\n${verifyUrl}\n\n— BudTut`,
    `<p>Cześć ${escapeHtml(req.user.first)},</p><p><a href="${verifyUrl}">${verifyUrl}</a></p>`);
  res.json({ ok: true });
});

// ----- Google Sign-In -----
// Step 1: verify the Google ID token. An existing account (matched by Google account id, or by an
// already-registered matching e-mail) logs straight in; a brand-new Google user gets their
// verified name/e-mail back so the frontend can collect the few fields Google doesn't provide
// (phone, birth date, gender, terms) before step 2 actually creates the account.
app.post('/api/auth/google', limit('google', 30, 60 * 60e3), async (req, res) => {
  if (!googleClient) return res.status(501).json({ error: 'google_not_configured' });
  const profile = await verifyGoogleToken(req.body && req.body.credential);
  if (!profile) return res.status(401).json({ error: 'invalid_token' });
  let user = db.users.find((u) => u.googleId === profile.sub && !u.deleted);
  if (!user) user = db.users.find((u) => u.email === profile.email && !u.deleted);
  if (user) {
    if (!user.googleId) user.googleId = profile.sub;
    if (!user.emailVerified) user.emailVerified = true;
    save();
    const token = createSession(user.id);
    return res.json({ token, user: publicUser(user), isNew: false });
  }
  res.json({ isNew: true, profile: { first: profile.first, last: profile.last, email: profile.email } });
});

// Step 2: create the account. Private-person accounts only -- sole-trader (JDG) and company
// accounts need the full business lookup/verification flow, which Google can't provide.
app.post('/api/auth/google/register', limit('google', 30, 60 * 60e3), async (req, res) => {
  if (!googleClient) return res.status(501).json({ error: 'google_not_configured' });
  const profile = await verifyGoogleToken(req.body && req.body.credential);
  if (!profile) return res.status(401).json({ error: 'invalid_token' });
  if (db.users.some((u) => u.googleId === profile.sub || u.email === profile.email)) {
    return res.status(409).json({ error: 'invalid', errors: { email: 'email_taken' } });
  }
  const b = req.body || {};
  const errors = {};
  const phone = clean(b.phone, 30);
  const digits = phone.replace(/\D/g, '');
  if (!phone) errors.phone = 'required';
  else if (!/^\+?[\d\s()-]+$/.test(phone) || digits.length < 9 || digits.length > 15) errors.phone = 'phone_invalid';
  const birthErr = birthCheck(b.birth); if (birthErr) errors.birth = birthErr;
  let gender = null;
  if (GENDERS.includes(b.gender)) gender = b.gender; else errors.gender = 'required';
  if (b.terms !== true) errors.terms = 'terms';
  const captchaOk = await verifyCaptcha(b.captcha, req.ip);
  if (!captchaOk) errors.captcha = 'captcha_invalid';
  if (Object.keys(errors).length) return res.status(400).json({ error: 'invalid', errors });

  const user = {
    id: uid(), type: 'person', gender, birth: b.birth, first: profile.first, last: profile.last, email: profile.email, phone,
    position: null, business: null, passHash: null, googleId: profile.sub, verified: false, emailVerified: true,
    createdAt: new Date().toISOString(),
  };
  db.users.push(user);
  const token = createSession(user.id);
  save();
  res.status(201).json({ token, user: publicUser(user) });
});

// Public, non-secret configuration the frontend needs (Google client id, reCAPTCHA site key).
// Both are safe to expose -- they identify the app to Google, neither authenticates anything.
app.get('/api/config', (req, res) => {
  res.json({ googleClientId: GOOGLE_CLIENT_ID || null, recaptchaSiteKey: RECAPTCHA_SITE_KEY || null });
});

// ----- Registry lookup (used by the registration form) -----
app.get('/api/lookup', limit('lookup', 60, 60e3), async (req, res) => {
  const type = req.query.type === 'jdg' ? 'jdg' : 'company';
  const found = await lookupCompany({ type, number: req.query.number, first: clean(req.query.first, 60), last: clean(req.query.last, 80) });
  if (!found) return res.status(404).json({ error: 'not_found' });
  res.json({ business: found });
});

// ----- Jobs -----
const publicJob = (j) => ({
  id: j.id, title: j.title, description: j.description, category: j.category, city: j.city, district: j.district,
  budget: j.budget, status: j.status || 'open', createdAt: j.createdAt, statusAt: j.statusAt || j.createdAt, offers: 0,
  author: { id: j.userId, first: j.authorFirst, verified: j.authorVerified },
});

app.get('/api/jobs', (req, res) => {
  // public listing shows only open jobs (still to be done) — completed jobs stay on the author's profile as history
  const list = db.jobs.filter((j) => (j.status || 'open') === 'open').sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map(publicJob);
  res.json({ jobs: list });
});

app.get('/api/jobs/mine', auth, (req, res) => {
  res.json({ jobs: db.jobs.filter((j) => j.userId === req.user.id).map(publicJob) });
});

app.get('/api/jobs/:id', (req, res) => {
  const j = db.jobs.find((x) => x.id === req.params.id);
  if (!j) return res.status(404).json({ error: 'not_found' });
  res.json({ job: publicJob(j) });
});

// Contact details of the client – only for logged-in users (free, but not shown to anonymous visitors / scrapers)
app.get('/api/jobs/:id/contact', auth, limit('jobcontact', 40, 60 * 60e3), (req, res) => {
  const j = db.jobs.find((x) => x.id === req.params.id);
  const u = j && db.users.find((x) => x.id === j.userId && !x.deleted);
  if (!u) return res.status(404).json({ error: 'not_found' });
  res.json({ contact: { name: displayName(u), email: u.email, phone: u.phone } });
});

app.post('/api/jobs', auth, limit('job', 30, 60 * 60e3), (req, res) => {
  const b = req.body || {};
  const errors = {};
  const title = clean(b.title, 120), description = cleanML(String(b.description ?? '').replace(/\r/g, ''), 2000);
  const district = clean(b.district, 60);
  if (title.length < 5) errors.title = title ? 'too_short' : 'required';
  if (description.length < 20) errors.description = description ? 'too_short' : 'required';
  if (!CATEGORIES.includes(b.category)) errors.category = 'required';
  if (!CITIES.includes(b.city)) errors.city = 'required';
  let budget = null;
  if (b.budget !== null && b.budget !== undefined && b.budget !== '') {
    budget = Number(b.budget);
    if (!Number.isInteger(budget) || budget < 0 || budget > 10000000) errors.budget = 'budget_invalid';
  }
  if (Object.keys(errors).length) return res.status(400).json({ error: 'invalid', errors });

  const job = {
    id: uid(), userId: req.user.id, authorFirst: req.user.first, authorVerified: !!req.user.verified,
    title, description, category: b.category, city: b.city, district, budget, status: 'open', statusAt: new Date().toISOString(), createdAt: new Date().toISOString(),
  };
  db.jobs.push(job); save();
  res.status(201).json({ job: publicJob(job) });
});

// Jobs are never deleted by their author — they stay as a history of posted work (open = to be done, done = completed).
app.patch('/api/jobs/:id/status', auth, limit('jobstatus', 60, 60 * 60e3), (req, res) => {
  const j = db.jobs.find((x) => x.id === req.params.id && x.userId === req.user.id);
  if (!j) return res.status(404).json({ error: 'not_found' });
  const status = req.body && req.body.status;
  if (status !== 'open' && status !== 'done') return res.status(400).json({ error: 'invalid', errors: { status: 'required' } });
  j.status = status; j.statusAt = new Date().toISOString(); save();
  res.json({ job: publicJob(j) });
});

// ----- Services (JDG / company offer these on their profile) -----
const publicService = (x) => ({ id: x.id, title: x.title, category: x.category, description: x.description, priceFrom: x.priceFrom, createdAt: x.createdAt });

app.post('/api/services', auth, limit('svc', 40, 60 * 60e3), (req, res) => {
  if (req.user.type === 'person') return res.status(403).json({ error: 'forbidden' });
  const b = req.body || {}, errors = {};
  const title = clean(b.title, 100), description = clean(String(b.description ?? '').replace(/\r/g, ''), 600);
  if (title.length < 3) errors.title = title ? 'too_short' : 'required';
  if (!CATEGORIES.includes(b.category)) errors.category = 'required';
  let priceFrom = null;
  if (b.priceFrom !== null && b.priceFrom !== undefined && b.priceFrom !== '') {
    priceFrom = Number(b.priceFrom);
    if (!Number.isInteger(priceFrom) || priceFrom < 0 || priceFrom > 10000000) errors.priceFrom = 'budget_invalid';
  }
  if (Object.keys(errors).length) return res.status(400).json({ error: 'invalid', errors });
  if (db.services.filter((x) => x.userId === req.user.id).length >= 30) return res.status(400).json({ error: 'invalid', errors: { title: 'too_many' } });
  const svc = { id: uid(), userId: req.user.id, title, category: b.category, description, priceFrom, createdAt: new Date().toISOString() };
  db.services.push(svc); save(); res.status(201).json({ service: publicService(svc) });
});
app.delete('/api/services/:id', auth, (req, res) => {
  const i = db.services.findIndex((x) => x.id === req.params.id && x.userId === req.user.id);
  if (i < 0) return res.status(404).json({ error: 'not_found' });
  db.services.splice(i, 1); save(); res.json({ ok: true });
});

// ----- Reviews (any account can review any other account after working together) -----
// TODO: once jobs have an accepted-offer / "done" state, only allow reviews between the two parties of a finished job.
const reviewAuthor = (id) => { const u = db.users.find((x) => x.id === id); if (u && u.deleted) return { id: u.id, deleted: true, avatarUrl: null, name: '', type: u.type || 'person', gender: null, verified: false }; return u ? { id: u.id, avatarUrl: avatarUrl(u), name: displayName(u), type: u.type, gender: u.gender || null, verified: !!u.verified } : { id, name: '—', type: 'person', gender: null, verified: false }; };
const publicReview = (r) => ({ id: r.id, rating: r.rating, text: r.text, work: r.work, createdAt: r.createdAt, author: reviewAuthor(r.authorId) });
function reviewSummary(list) {
  const n = list.length, avg = n ? list.reduce((a, r) => a + r.rating, 0) / n : 0;
  return { count: n, average: Math.round(avg * 10) / 10 };
}

// Public profile (no e-mail / phone here)
app.get('/api/users/:id/profile', (req, res) => {
  const u = db.users.find((x) => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'user_not_found' });
  if (u.deleted) {
    const dr = db.reviews.filter((r) => r.targetId === u.id).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return res.json({ user: { id: u.id, deleted: true, type: u.type || 'person', gender: null, name: '', verified: false, createdAt: u.createdAt, avatarUrl: null, city: null }, services: [], jobs: [], reviews: dr.map(publicReview), summary: reviewSummary(dr) });
  }
  const revs = db.reviews.filter((r) => r.targetId === u.id).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  res.json({
    user: { id: u.id, avatarUrl: avatarUrl(u), type: u.type, gender: u.gender || null, name: displayName(u), verified: !!u.verified, createdAt: u.createdAt, city: u.business && u.business.city || null },
    services: db.services.filter((x) => x.userId === u.id).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map(publicService),
    jobs: db.jobs.filter((j) => j.userId === u.id).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map(publicJob),
    reviews: revs.map(publicReview), summary: reviewSummary(revs),
  });
});

app.post('/api/users/:id/reviews', auth, limit('rev', 30, 60 * 60e3), (req, res) => {
  const target = db.users.find((x) => x.id === req.params.id);
  if (!target || target.deleted) return res.status(404).json({ error: 'not_found' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'invalid', errors: { rating: 'self' } });
  const b = req.body || {}, errors = {};
  const rating = Number(b.rating), text = clean(String(b.text ?? '').replace(/\r/g, ''), 1000), work = clean(b.work, 120);
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) errors.rating = 'required';
  if (text.length < 10) errors.text = text ? 'too_short' : 'required';
  if (Object.keys(errors).length) return res.status(400).json({ error: 'invalid', errors });
  if (db.reviews.some((r) => r.targetId === target.id && r.authorId === req.user.id)) return res.status(409).json({ error: 'invalid', errors: { rating: 'already' } });
  const r = { id: uid(), targetId: target.id, authorId: req.user.id, rating, text, work, createdAt: new Date().toISOString() };
  db.reviews.push(r); save(); res.status(201).json({ review: publicReview(r) });
});

app.delete('/api/reviews/:id', auth, (req, res) => {
  const i = db.reviews.findIndex((r) => r.id === req.params.id && r.authorId === req.user.id);
  if (i < 0) return res.status(404).json({ error: 'not_found' });
  db.reviews.splice(i, 1); save(); res.json({ ok: true });
});

// ----- Verification requests -----
// Identity (PESEL) is checked for format only and is NEVER stored. Requests stay "pending" until reviewed.
// TODO: real checks (CEIDG / KRS / mObywatel or an identity provider), manual review screen, then set user.verified = true.
function peselInfo(p) {
  if (!/^\d{11}$/.test(p)) return null;
  const w = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
  let sum = 0; for (let i = 0; i < 10; i++) sum += w[i] * Number(p[i]);
  if ((10 - (sum % 10)) % 10 !== Number(p[10])) return null;
  let yy = Number(p.slice(0, 2)), mm = Number(p.slice(2, 4)); const dd = Number(p.slice(4, 6));
  const cent = { 0: 1900, 2: 2000, 4: 2100, 6: 2200, 8: 1800 }[Math.floor(mm / 20) * 2];
  if (cent === undefined) return null;
  mm = mm % 20; const year = cent + yy;
  const d = new Date(Date.UTC(year, mm - 1, dd));
  if (d.getUTCFullYear() !== year || d.getUTCMonth() !== mm - 1 || d.getUTCDate() !== dd) return null;
  return { year, month: mm, day: dd };
}
app.get('/api/verification/mine', auth, (req, res) => {
  const list = db.verifications.filter((v) => v.userId === req.user.id).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  res.json({ verified: !!req.user.verified, request: list[0] ? { id: list[0].id, type: list[0].type, status: list[0].status, createdAt: list[0].createdAt, name: list[0].name } : null });
});
app.post('/api/verification', auth, limit('verif', 10, 60 * 60e3), async (req, res) => {
  const b = req.body || {}, errors = {};
  if (!TYPES.includes(b.type)) return res.status(400).json({ error: 'invalid', errors: { type: 'required' } });
  if (req.user.verified) return res.status(409).json({ error: 'already_verified' });
  if (db.verifications.some((v) => v.userId === req.user.id && v.status === 'pending')) return res.status(409).json({ error: 'already_pending' });
  const first = clean(b.first, 60), last = clean(b.last, 80);
  if (!first) errors.first = 'required';
  if (!last) errors.last = 'required';
  const rec = { id: uid(), userId: req.user.id, type: b.type, status: 'pending', createdAt: new Date().toISOString(), name: '' };
  if (b.type === 'person') {
    const info = peselInfo(String(b.pesel || '').replace(/\s/g, ''));
    if (!info) errors.pesel = 'pesel_invalid';
    else {
      const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(b.birth || ''));
      if (!m) errors.birth = 'required';
      else if (+m[1] !== info.year || +m[2] !== info.month || +m[3] !== info.day) errors.birth = 'birth_mismatch';
      else if (Date.now() < Date.UTC(info.year + 18, info.month - 1, info.day)) errors.birth = 'underage';
      else if (req.user.birth && req.user.birth !== b.birth) errors.birth = 'birth_mismatch';
    }
    rec.name = `${first} ${last}`;
  } else {
    const biz = await lookupCompany({ type: b.type, number: b.business && b.business.number, first, last });
    if (!biz) errors.business = 'business_invalid'; else if (!b.business.confirmed) errors.business = 'business_unconfirmed';
    else {
      rec.business = { name: biz.name, nip: biz.nip, krs: biz.krs || null };
      rec.name = biz.name; rec.source = biz.source || null;
      if (biz.repMatch !== undefined) rec.repMatch = biz.repMatch;
    }
    if (b.type === 'company') {
      if (!POSITIONS.includes(b.position)) errors.position = 'required'; else rec.position = b.position;
      if (b.authority !== true) errors.authority = 'authority';
    }
  }
  if (b.consent !== true) errors.consent = 'consent';
  if (Object.keys(errors).length) return res.status(400).json({ error: 'invalid', errors });
  rec.applicant = `${first} ${last}`;
  db.verifications.push(rec); save();
  res.status(201).json({ request: { id: rec.id, type: rec.type, status: rec.status, createdAt: rec.createdAt, name: rec.name } });
});

// ---------- Profile photo / company logo ----------
const AVATAR_MAX = 300 * 1024;
function sniffImage(buf) {
  if (buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.length > 8 && buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buf.length > 12 && buf.slice(0, 4).toString() === 'RIFF' && buf.slice(8, 12).toString() === 'WEBP') return 'image/webp';
  return null;
}
app.put('/api/me/avatar', auth, limit('avatar', 20, 60 * 60e3), (req, res) => {
  const m = /^data:image\/(?:jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String((req.body || {}).image || ''));
  if (!m) return res.status(400).json({ error: 'invalid', errors: { image: 'format' } });
  const buf = Buffer.from(m[1], 'base64');
  if (buf.length > AVATAR_MAX) return res.status(413).json({ error: 'invalid', errors: { image: 'too_big' } });
  const mime = sniffImage(buf);
  if (!mime) return res.status(400).json({ error: 'invalid', errors: { image: 'format' } });
  req.user.avatar = 'data:' + mime + ';base64,' + m[1]; req.user.avatarV = Date.now().toString(36);
  save();
  res.json({ avatarUrl: avatarUrl(req.user) });
});
app.delete('/api/me/avatar', auth, (req, res) => {
  delete req.user.avatar; delete req.user.avatarV; save();
  res.json({ avatarUrl: null });
});
app.get('/api/users/:id/avatar', (req, res) => {
  const u = db.users.find((x) => x.id === req.params.id);
  const m = u && u.avatar && /^data:(image\/[a-z]+);base64,(.+)$/.exec(u.avatar);
  if (!m) return res.status(404).end();
  res.set({ 'Content-Type': m[1], 'Cache-Control': 'public, max-age=604800', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; sandbox" });
  res.send(Buffer.from(m[2], 'base64'));
});

// ---------- Account settings ----------
app.patch('/api/me', auth, limit('me', 30, 60 * 60e3), (req, res) => {
  const b = req.body || {}, errors = {}, u = req.user;
  const first = b.first === undefined ? u.first : clean(b.first, 60), last = b.last === undefined ? u.last : clean(b.last, 80);
  const phone = b.phone === undefined ? u.phone : clean(b.phone, 30);
  if (!first) errors.first = 'required';
  if (!last) errors.last = 'required';
  if (u.verified && (first !== u.first || last !== u.last)) errors.first = 'locked_verified';
  const digits = phone.replace(/\D/g, '');
  if (!phone) errors.phone = 'required';
  else if (!/^\+?[\d\s()-]+$/.test(phone) || digits.length < 9 || digits.length > 15) errors.phone = 'phone_invalid';
  let gender = u.gender || null;
  if (u.type !== 'company' && b.gender !== undefined) { if (GENDERS.includes(b.gender)) gender = b.gender; else errors.gender = 'required'; }
  let birth = u.birth || null;
  if (b.birth !== undefined && b.birth !== u.birth) { if (u.verified) errors.birth = 'locked_verified'; else { const be = birthCheck(b.birth); if (be) errors.birth = be; else birth = b.birth; } }
  if (Object.keys(errors).length) return res.status(400).json({ error: 'invalid', errors });
  u.birth = birth; u.first = first; u.last = last; u.phone = phone; if (u.type !== 'company') u.gender = gender;
  db.jobs.forEach((j) => { if (j.userId === u.id) j.authorFirst = first; });
  save(); res.json({ user: publicUser(u) });
});
app.post('/api/me/password', auth, limit('pw', 10, 15 * 60e3), (req, res) => {
  const b = req.body || {}, errors = {};
  const cur = String(b.current ?? ''), next = String(b.next ?? '');
  if (!cur || !verifyPassword(cur, req.user.passHash)) errors.current = 'wrong_password';
  if (!next) errors.next = 'required'; else if (next.length < 8 || next.length > 200) errors.next = 'password_short'; else if (next === cur) errors.next = 'password_same';
  if (Object.keys(errors).length) return res.status(400).json({ error: 'invalid', errors });
  req.user.passHash = hashPassword(next);
  db.sessions = db.sessions.filter((x) => x.userId !== req.user.id || x.h === req.tokenHash); // sign out other devices
  save(); res.json({ ok: true });
});
app.post('/api/me/logout-all', auth, (req, res) => {
  db.sessions = db.sessions.filter((x) => x.userId !== req.user.id || x.h === req.tokenHash);
  save(); res.json({ ok: true });
});
// GDPR art. 15 / 20 – copy of the user's data in a machine-readable format
app.get('/api/me/export', auth, limit('export', 10, 60 * 60e3), (req, res) => {
  const u = req.user, { passHash, avatar, ...profile } = u; // eslint-disable-line no-unused-vars
  const out = {
    exportedAt: new Date().toISOString(), profile: { ...profile, hasAvatar: !!avatar },
    jobs: db.jobs.filter((j) => j.userId === u.id),
    services: db.services.filter((x) => x.userId === u.id),
    reviewsWritten: db.reviews.filter((r) => r.authorId === u.id),
    reviewsReceived: db.reviews.filter((r) => r.targetId === u.id).map((r) => ({ id: r.id, rating: r.rating, text: r.text, work: r.work, createdAt: r.createdAt })),
    verificationRequests: db.verifications.filter((v) => v.userId === u.id).map((v) => ({ id: v.id, type: v.type, status: v.status, createdAt: v.createdAt, name: v.name, business: v.business || null })),
    contactMessages: db.contacts.filter((c) => c.userId === u.id || c.email === u.email),
    reports: db.reports.filter((r) => r.userId === u.id),
  };
  res.set({ 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': 'attachment; filename="budtut-my-data.json"' });
  res.send(JSON.stringify(out, null, 2));
});
// GDPR art. 17 – erasure is done on request, after a manual check by the operator (see admin section below)
app.get('/api/me/deletion-request', auth, (req, res) => {
  const r = db.deletionRequests.filter((x) => x.userId === req.user.id).sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
  res.json({ request: r ? { ref: r.ref, status: r.status, createdAt: r.createdAt, decidedAt: r.decidedAt || null } : null });
});
app.post('/api/me/deletion-request', auth, limit('delreq', 5, 60 * 60e3), (req, res) => {
  const pw = String((req.body && req.body.password) ?? '');
  if (!pw || !verifyPassword(pw, req.user.passHash)) return res.status(400).json({ error: 'invalid', errors: { password: 'wrong_password' } });
  if (db.deletionRequests.some((x) => x.userId === req.user.id && x.status === 'pending')) return res.status(409).json({ error: 'already_pending' });
  const rec = { id: uid(), ref: refNo('U'), userId: req.user.id, email: req.user.email, name: displayName(req.user), reason: cleanML((req.body || {}).reason, 1000), status: 'pending', createdAt: new Date().toISOString() };
  db.deletionRequests.push(rec); save();
  res.status(201).json({ request: { ref: rec.ref, status: rec.status, createdAt: rec.createdAt } });
});
app.delete('/api/me/deletion-request', auth, (req, res) => {
  const r = db.deletionRequests.find((x) => x.userId === req.user.id && x.status === 'pending');
  if (!r) return res.status(404).json({ error: 'not_found' });
  r.status = 'withdrawn'; r.decidedAt = new Date().toISOString(); save(); res.json({ ok: true });
});

// ---------- Admin (disabled unless ADMIN_TOKEN is set) ----------
function admin(req, res, next) {
  const t = process.env.ADMIN_TOKEN;
  if (!t || t.length < 16) return res.status(404).json({ error: 'not_found' });
  const given = Buffer.from(String(req.get('X-Admin-Token') || '')), want = Buffer.from(t);
  if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) return res.status(401).json({ error: 'unauthorized' });
  next();
}
app.get('/api/admin/deletion-requests', admin, (req, res) => {
  res.json({ requests: db.deletionRequests.map((r) => {
    const u = db.users.find((x) => x.id === r.userId);
    return { ref: r.ref, status: r.status, createdAt: r.createdAt, decidedAt: r.decidedAt || null, name: r.name, email: r.email, reason: r.reason,
      jobs: db.jobs.filter((j) => j.userId === r.userId).length, services: db.services.filter((x) => x.userId === r.userId).length,
      reviewsWritten: db.reviews.filter((x) => x.authorId === r.userId).length, reviewsReceived: db.reviews.filter((x) => x.targetId === r.userId).length,
      verified: !!(u && u.verified), pendingReports: db.reports.filter((x) => x.userId === r.userId).length };
  }) });
});
// Erasure keeps reviews (given and received). The account becomes an anonymous "deleted user" tombstone.
function eraseUser(id) {
  const u = db.users.find((x) => x.id === id); if (!u) return false;
  db.jobs = db.jobs.filter((x) => x.userId !== id);
  db.services = db.services.filter((x) => x.userId !== id);
  db.verifications = db.verifications.filter((x) => x.userId !== id);
  db.sessions = db.sessions.filter((x) => x.userId !== id);
  db.contacts.forEach((c) => { if (c.userId === id) { c.userId = null; c.name = ''; c.email = ''; } });
  db.reports.forEach((r) => { if (r.userId === id) r.userId = null; });
  const keep = { id: u.id, type: u.type, createdAt: u.createdAt };
  Object.keys(u).forEach((k) => delete u[k]);
  Object.assign(u, keep, { deleted: true, deletedAt: new Date().toISOString(), verified: false });
  return true;
}
app.post('/api/admin/deletion-requests/:ref/:action', admin, (req, res) => {
  const r = db.deletionRequests.find((x) => x.ref === req.params.ref);
  if (!r) return res.status(404).json({ error: 'not_found' });
  if (r.status !== 'pending') return res.status(409).json({ error: 'already_decided', status: r.status });
  if (req.params.action === 'approve') { eraseUser(r.userId); r.status = 'approved'; r.email = ''; r.name = ''; r.reason = ''; }
  else if (req.params.action === 'reject') { r.status = 'rejected'; r.note = cleanML((req.body || {}).note, 500); }
  else return res.status(404).json({ error: 'not_found' });
  r.decidedAt = new Date().toISOString(); save(); res.json({ ok: true, status: r.status });
});

// Pending identity/business verification requests (created by POST /api/verification).
// Approving sets user.verified = true; this is the missing other half of that TODO.
app.get('/api/admin/verifications', admin, (req, res) => {
  res.json({ requests: db.verifications.map((v) => {
    const u = db.users.find((x) => x.id === v.userId);
    return {
      id: v.id, type: v.type, status: v.status, createdAt: v.createdAt, name: v.name,
      applicant: v.applicant || null, business: v.business || null,
      repMatch: v.repMatch === undefined ? null : v.repMatch, source: v.source || null,
      position: v.position || null, email: u ? u.email : null, currentlyVerified: !!(u && u.verified),
    };
  }) });
});
app.post('/api/admin/verifications/:id/:action', admin, (req, res) => {
  const v = db.verifications.find((x) => x.id === req.params.id);
  if (!v) return res.status(404).json({ error: 'not_found' });
  if (v.status !== 'pending') return res.status(409).json({ error: 'already_decided', status: v.status });
  if (req.params.action === 'approve') {
    const u = db.users.find((x) => x.id === v.userId);
    if (u) u.verified = true;
    v.status = 'approved';
  } else if (req.params.action === 'reject') {
    v.status = 'rejected'; v.note = cleanML((req.body || {}).note, 500);
  } else return res.status(404).json({ error: 'not_found' });
  v.decidedAt = new Date().toISOString(); save();
  res.json({ ok: true, status: v.status });
});

// ---------- Contact form & DSA notices ----------
const cleanML = (v, max) => String(v ?? '').replace(/[\u0000-\u0009\u000b-\u001f\u007f]/g, ' ').trim().slice(0, max);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
function optUser(req) {
  const m = /^Bearer (\w{64})$/.exec(req.get('Authorization') || '');
  if (!m) return null;
  const s = db.sessions.find((x) => x.h === sha(m[1]) && x.exp > Date.now());
  return (s && db.users.find((u) => u.id === s.userId)) || null;
}
const refNo = (p) => p + '-' + new Date().getFullYear() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase();
const CONTACT_TOPICS = ['general', 'account', 'jobs', 'verification', 'business', 'press', 'privacy', 'other'];
app.post('/api/contact', limit('contact', 5, 60 * 60e3), (req, res) => {
  const b = req.body || {}, errors = {};
  const name = clean(b.name, 100), email = clean(b.email, 160), message = cleanML(b.message, 4000);
  if (b.website) return res.status(201).json({ ref: refNo('K') }); // honeypot: pretend success
  if (!name) errors.name = 'required';
  if (!email) errors.email = 'required'; else if (!EMAIL_RE.test(email)) errors.email = 'email_bad';
  if (!CONTACT_TOPICS.includes(b.topic)) errors.topic = 'required';
  if (message.length < 10) errors.message = message ? 'short' : 'required';
  if (b.consent !== true) errors.consent = 'consent';
  if (Object.keys(errors).length) return res.status(400).json({ error: 'invalid', errors });
  const u = optUser(req);
  const rec = { id: uid(), ref: refNo('K'), createdAt: new Date().toISOString(), name, email, topic: b.topic, message, userId: u ? u.id : null, status: 'new' };
  db.contacts.push(rec); save();
  res.status(201).json({ ref: rec.ref });
});
const REPORT_TYPES = ['illegal', 'fraud', 'review', 'harassment', 'ip', 'privacy', 'bug', 'other'];
app.post('/api/reports', limit('report', 8, 60 * 60e3), (req, res) => {
  const b = req.body || {}, errors = {};
  const email = clean(b.email, 160), url = clean(b.url, 500), description = cleanML(b.description, 5000), name = clean(b.name, 100), reason = cleanML(b.reason, 2000);
  if (b.website) return res.status(201).json({ ref: refNo('Z') });
  if (!REPORT_TYPES.includes(b.type)) errors.type = 'required';
  if (description.length < 10) errors.description = description ? 'short' : 'required';
  if (email && !EMAIL_RE.test(email)) errors.email = 'email_bad';
  if (['illegal', 'fraud', 'review', 'harassment', 'ip', 'privacy'].includes(b.type) && !email) errors.email = 'required';
  if (b.statement !== true) errors.statement = 'consent';
  if (Object.keys(errors).length) return res.status(400).json({ error: 'invalid', errors });
  const u = optUser(req);
  const rec = { id: uid(), ref: refNo('Z'), createdAt: new Date().toISOString(), type: b.type, url, description, reason, name, email, userId: u ? u.id : null, status: 'received' };
  db.reports.push(rec); save();
  res.status(201).json({ ref: rec.ref });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'not_found' }));

// ----- Frontend -----
// The whole site is one page with a hash-based router (#jobs, #profile, ...), so the browser
// never actually requests those paths from the server — but a stray deep link, crawler hit, or a
// page reload after a proxy rewrite could still ask for an arbitrary path. Serve the app for any
// of those instead of a bare 404.
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// JSON error handler (bad JSON etc.)
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'bad_json' });
  console.error(err); res.status(500).json({ error: 'server_error' });
});

app.listen(PORT, () => console.log(`BudTut running at http://localhost:${PORT}`));
