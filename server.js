'use strict';
// ShareLab backend: libSQL / Turso & SQLite compatible.
const http = require('node:http'), fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');

const PORT = process.env.PORT || 3000;
const isServerless = Boolean(
  process.env.VERCEL ||
  process.env.VERCEL_ENV ||
  process.env.NOW_REGION ||
  process.env.AWS_LAMBDA_FUNCTION_NAME ||
  process.env.LAMBDA_TASK_ROOT ||
  (typeof __dirname === 'string' && __dirname.startsWith('/var/task'))
);

function getClient() {
  if (process.env.TURSO_DATABASE_URL) {
    const { createClient } = require('@libsql/client/web');
    return createClient({
      url: process.env.TURSO_DATABASE_URL,
      authToken: process.env.TURSO_AUTH_TOKEN,
    });
  }
  if (isServerless) {
    // If running on Vercel without Turso credentials, use web client or warn
    throw new Error('TURSO_DATABASE_URL is missing. Please configure TURSO_DATABASE_URL and TURSO_AUTH_TOKEN in Vercel Environment Variables.');
  }
  const { createClient } = require('@libsql/client');
  const dbPath = process.env.DB_PATH || path.join(__dirname, 'sharelab.db');
  return createClient({ url: 'file:' + dbPath });
}

let clientInstance = null;
const client = new Proxy({}, {
  get(_, prop) {
    if (!clientInstance) clientInstance = getClient();
    const val = clientInstance[prop];
    return typeof val === 'function' ? val.bind(clientInstance) : val;
  }
});

const txStorage = new AsyncLocalStorage();
const target = () => txStorage.getStore() || client;

const all = async (s, ...a) => (await target().execute({ sql: s, args: a })).rows;
const one = async (s, ...a) => (await target().execute({ sql: s, args: a })).rows[0];
const run = async (s, ...a) => target().execute({ sql: s, args: a });

async function withTx(fn) {
  const tx = await client.transaction('write');
  try {
    const res = await txStorage.run(tx, fn);
    await tx.commit();
    return res;
  } catch (e) {
    try { await tx.rollback(); } catch {}
    throw e;
  }
}

let initPromise = null;
async function initDb() {
  await client.executeMultiple(`
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name,email UNIQUE,role,pw,verified INT DEFAULT 1,late INT DEFAULT 0,noshow INT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS creds(u,k,st,PRIMARY KEY(u,k));
    CREATE TABLE IF NOT EXISTS res(id TEXT PRIMARY KEY,n,c,l,o,m,req,mode,q INT,rule,active INT DEFAULT 1);
    CREATE TABLE IF NOT EXISTS bk(id TEXT PRIMARY KEY,r,u,day,s INT,h INT,purpose,st,why,t INT,ci,co,late INT DEFAULT 0,ovd INT DEFAULT 0,rem INT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS inc(id TEXT PRIMARY KEY,b,t,s,d,st,rep,res DEFAULT '',at INT);
    CREATE TABLE IF NOT EXISTS notif(id INTEGER PRIMARY KEY AUTOINCREMENT,u,m,t INT,seen INT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,t INT,who,act,ent,why,p,h);
    CREATE TABLE IF NOT EXISTS sess(tok TEXT PRIMARY KEY,u,exp INT);
    CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v INT);
  `);
  await seed();
}
const ensureInit = () => (initPromise = initPromise || initDb());
if (!isServerless) {
  ensureInit().catch(console.error);
}

const CRED = { safety: 'Makerspace safety training', electronics: 'Electronics lab induction', cnc: 'CNC operator certificate' };
const CATS = ['Makerspace', 'Electronics', 'Computing', 'Rooms', 'Media'], CONDS = ['Excellent', 'Good', 'Worn', 'Damaged'];
const ACT = "('pending','approved','checkedout')", USED = "('pending','approved','checkedout','returned')";
const INC_T = ['Damage', 'Late return', 'No-show', 'Misuse', 'Safety', 'Conflict'], SEV = ['Low', 'Medium', 'High'];
const OUT = ['Resolved: no penalty', 'Resolved: warning issued', 'Resolved: deposit deduction approved', 'Dismissed'];
const pad = n => String(n).padStart(2, '0');
const localDay = (off = 0) => { const d = new Date(); d.setDate(d.getDate() + off); return new Date(d - d.getTimezoneOffset() * 6e4).toISOString().slice(0, 10); };
const bad = (m, c = 400) => { const e = new Error(m); e.code = c; throw e; };
const nextId = async p => {
  await run('INSERT INTO meta(k,v) VALUES(?,100) ON CONFLICT(k) DO UPDATE SET v=v+1', 'seq');
  const row = await one("SELECT v FROM meta WHERE k='seq'");
  return p + row.v;
};

// ---------- security helpers ----------
const hashPw = pw => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(pw, s, 32).toString('hex'); };
const checkPw = (pw, st) => { const [s, h] = st.split(':'); const x = crypto.scryptSync(pw, s, 32); return crypto.timingSafeEqual(x, Buffer.from(h, 'hex')); };
const attempts = new Map();
const limited = ip => { const n = Date.now(), a = (attempts.get(ip) || []).filter(t => n - t < 6e4); a.push(n); attempts.set(ip, a); return a.length > 10; };

// ---------- audit (append-only, hash-chained) ----------
async function log(act, ent, why, who) {
  const last = await one('SELECT h FROM audit ORDER BY id DESC LIMIT 1'), p = last ? last.h : '0', t = Date.now(), w = String(why || '').slice(0, 500);
  const h = crypto.createHash('sha256').update(p + JSON.stringify([t, who, act, ent, w])).digest('hex').slice(0, 16);
  await run('INSERT INTO audit(t,who,act,ent,why,p,h) VALUES(?,?,?,?,?,?,?)', t, who, act, ent, w, p, h);
}
async function verifyChain() {
  let p = '0', ok = true; const rows = await all('SELECT * FROM audit ORDER BY id');
  for (const e of rows) { const h = crypto.createHash('sha256').update(p + JSON.stringify([e.t, e.who, e.act, e.ent, e.why])).digest('hex').slice(0, 16); if (e.p !== p || e.h !== h) ok = false; p = e.h; }
  return { ok, events: rows.length };
}
const note = async (u, m) => run('INSERT INTO notif(u,m,t) VALUES(?,?,?)', u, m, Date.now());

// ---------- domain logic ----------
const R = async id => { const r = await one('SELECT * FROM res WHERE id=?', id); if (!r) bad('Resource not found', 404); r.req = JSON.parse(r.req); return r; };
const B = async id => (await one('SELECT * FROM bk WHERE id=?', id)) || bad('Booking not found', 404);
const canR = (me, r) => me.role === 'admin' || r.o === me.id || r.m === me.id;
const credOf = async u => Object.fromEntries((await all('SELECT k,st FROM creds WHERE u=?', u)).map(c => [c.k, c.st]));
const conflict = async (r, d, s, h, ex) => await one(`SELECT * FROM bk WHERE r=? AND id!=? AND st IN ${ACT} AND day=? AND ?<s+h AND s<?`, r, ex || '', d, s, s + h);
const used = async (u, r, ex) => (await one(`SELECT COALESCE(SUM(h),0) v FROM bk WHERE u=? AND r=? AND id!=? AND st IN ${USED}`, u, r, ex || '')).v;
const score = async u => { const x = await one('SELECT late,noshow FROM users WHERE id=?', u); return (await one(`SELECT COALESCE(SUM(h),0) v FROM bk WHERE u=? AND st IN ${USED}`, u)).v + 5 * x.late + 3 * x.noshow; };
const endMs = b => new Date(b.day + 'T00:00').getTime() + (b.s + b.h) * 36e5, startMs = b => new Date(b.day + 'T00:00').getTime() + b.s * 36e5;
async function pre(uid, r, d, s, h, ex) {
  const cr = await credOf(uid), c = await conflict(r.id, d, s, h, ex), us = await used(uid, r.id, ex), quota = us + h <= r.q;
  const valid = /^\d{4}-\d{2}-\d{2}$/.test(d) && d >= localDay() && s >= 8 && s + h <= 20 && h >= 1;
  const checks = [...r.req.map(k => ({ ok: cr[k] === 'verified', l: CRED[k], m: cr[k] === 'verified' ? 'Verified' : cr[k] === 'pending' ? 'Awaiting verification' : 'Not held' })),
    { ok: quota, l: 'Weekly quota', m: `${us + h} of ${r.q} h` },
    { ok: !c, l: 'Slot free', m: c ? `Taken ${pad(c.s)}:00-${pad(c.s + c.h)}:00` : 'No conflict' },
    { ok: valid, l: 'Opening hours 08:00-20:00, not in the past', m: valid ? 'Within hours' : 'Outside hours' }];
  return { checks, elig: r.req.every(k => cr[k] === 'verified'), quota, free: !c, valid };
}
async function promote(rid) { // waiting list: lowest recent usage first, then first come
  const r = await R(rid); let go = true;
  while (go) {
    go = false;
    const q = await all("SELECT * FROM bk WHERE r=? AND st='waitlisted'", rid);
    const scored = await Promise.all(q.map(async b => ({ b, s: await score(b.u) })));
    scored.sort((a, c) => a.s - c.s || a.b.t - c.b.t);
    for (const { b } of scored) {
      if (!(await conflict(rid, b.day, b.s, b.h, b.id)) && (await used(b.u, rid, b.id)) + b.h <= r.q && b.day >= localDay()) {
        const st = r.mode === 'auto' ? 'approved' : 'pending', why = 'Promoted from waiting list: lowest recent usage first';
        await run('UPDATE bk SET st=?,why=? WHERE id=?', st, why, b.id);
        await note(b.u, `${r.n}: you left the waiting list (${st}).`);
        await log('promoted', b.id, why, 'sys');
        go = true;
        break;
      }
    }
  }
}
async function tick() { // overdue + reminder jobs
  const now = Date.now();
  const checkedOut = await all("SELECT * FROM bk WHERE st='checkedout' AND ovd=0");
  for (const b of checkedOut) if (endMs(b) < now) {
    const r = await R(b.r); await run('UPDATE bk SET ovd=1 WHERE id=?', b.id);
    await Promise.all([b.u, r.o, r.m].map(u => note(u, `${r.n}: return is overdue (due ${pad(b.s + b.h)}:00 on ${b.day})`)));
    await log('overdue-flagged', b.id, 'Return time passed. Flagged for human review, no automatic penalty.', 'sys');
  }
  const approved = await all("SELECT * FROM bk WHERE st='approved' AND rem=0");
  for (const b of approved) if (startMs(b) - now < 36e5 && startMs(b) > now - 36e5) {
    const r = await R(b.r);
    await run('UPDATE bk SET rem=1 WHERE id=?', b.id);
    await note(b.u, `${r.n}: your slot starts at ${pad(b.s)}:00 on ${b.day}`);
  }
}

const str = (v, n = 300) => String(v ?? '').trim().slice(0, n);
const oneOf = (v, list, label) => list.includes(v) ? v : bad('Invalid ' + label);
const ACTS = {
  async submit(me, p) {
    if (me.role !== 'user') bad('Only student accounts can request resources', 403);
    const r = await R(p.r), s = +p.s, h = +p.h, d = str(p.day, 10), purpose = str(p.purpose);
    if (!purpose) bad('Add a purpose so the owner can review');
    if (!Number.isInteger(s) || !Number.isInteger(h) || h > 8) bad('Invalid time');
    const c = await pre(me.id, r, d, s, h);
    if (!c.elig) bad('You do not meet the eligibility requirements'); if (!c.valid) bad('Choose a future slot within opening hours');
    const id = await nextId('B'); let st, why;
    if (!c.quota || !c.free) { st = 'waitlisted'; why = `Waitlisted: ${[!c.free && 'slot already taken', !c.quota && 'weekly quota reached'].filter(Boolean).join(' and ')}. Priority: lowest recent usage first.`; }
    else if (r.mode === 'auto') { st = 'approved'; why = 'Auto-approved: all requirements met'; }
    else { st = 'pending'; why = 'Passed automatic checks; awaiting owner review'; }
    await run('INSERT INTO bk(id,r,u,day,s,h,purpose,st,why,t) VALUES(?,?,?,?,?,?,?,?,?,?)', id, r.id, me.id, d, s, h, purpose, st, why, Date.now());
    await log('requested', id, why, me.id); await note(me.id, `${r.n}: ${st}. ${why}`);
    if (st === 'pending') { await note(r.o, `New request for ${r.n}`); await note(r.m, `New request for ${r.n}`); }
    return { id, st };
  },
  async approve(me, p) {
    const b = await B(p.id), r = await R(b.r); if (!canR(me, r)) bad('Not allowed', 403);
    if (!['pending', 'waitlisted'].includes(b.st)) bad('Request is not awaiting a decision');
    if (await conflict(b.r, b.day, b.s, b.h, b.id)) bad('Slot is now taken by another booking');
    const why = 'Approved by ' + me.name + (b.st === 'waitlisted' ? ' (reviewer override of waiting list)' : '');
    await run("UPDATE bk SET st='approved',why=? WHERE id=?", why, b.id); await note(b.u, `${r.n}: approved for ${b.day} ${pad(b.s)}:00`); await log('approved', b.id, why, me.id);
  },
  async reject(me, p) {
    const b = await B(p.id), r = await R(b.r); if (!canR(me, r)) bad('Not allowed', 403); const w = str(p.w); if (!w) bad('A reason is required');
    if (!['pending', 'waitlisted', 'approved'].includes(b.st)) bad('Cannot reject at this stage');
    await run("UPDATE bk SET st='rejected',why=? WHERE id=?", 'Rejected: ' + w, b.id); await note(b.u, `${r.n}: rejected. ${w}`); await log('rejected', b.id, w, me.id); await promote(b.r);
  },
  async wl(me, p) {
    const b = await B(p.id), r = await R(b.r); if (!canR(me, r)) bad('Not allowed', 403); const w = str(p.w); if (!w) bad('A reason is required');
    if (b.st !== 'pending') bad('Only pending requests can be waitlisted');
    await run("UPDATE bk SET st='waitlisted',why=? WHERE id=?", 'Waitlisted by reviewer: ' + w, b.id); await note(b.u, `${r.n}: waitlisted. ${w}`); await log('waitlisted', b.id, w, me.id);
  },
  async cancel(me, p) {
    const b = await B(p.id), r = await R(b.r); if (!(canR(me, r) || b.u === me.id)) bad('Not allowed', 403);
    if (!['pending', 'waitlisted', 'approved'].includes(b.st)) bad('Cannot cancel at this stage');
    const why = 'Cancelled by ' + me.name; await run("UPDATE bk SET st='cancelled',why=? WHERE id=?", why, b.id); await log('cancelled', b.id, why, me.id);
    if (b.u !== me.id) await note(b.u, `${r.n}: booking cancelled`); await promote(b.r);
  },
  async ci(me, p) {
    const b = await B(p.id), r = await R(b.r); if (!(canR(me, r) || b.u === me.id)) bad('Not allowed', 403); if (b.st !== 'approved') bad('Booking is not approved');
    const c = oneOf(p.c, CONDS, 'condition'), n = str(p.n);
    await run("UPDATE bk SET st='checkedout',why='In use since check-in',ci=? WHERE id=?", JSON.stringify({ c, n, by: me.id, t: Date.now() }), b.id); await log('checked-in', b.id, `Condition: ${c}. ${n}`, me.id);
  },
  async co(me, p) {
    const b = await B(p.id), r = await R(b.r); if (!(canR(me, r) || b.u === me.id)) bad('Not allowed', 403); if (b.st !== 'checkedout') bad('Booking is not checked out');
    const c = oneOf(p.c, CONDS, 'condition'), n = str(p.n), ci = JSON.parse(b.ci || '{}');
    const worse = CONDS.indexOf(c) > CONDS.indexOf(ci.c), late = endMs(b) < Date.now() ? 1 : 0;
    const why = worse ? `Returned in worse condition (${ci.c} to ${c}). Review recommended.` : 'Returned, condition unchanged or better';
    await run("UPDATE bk SET st='returned',why=?,co=?,late=? WHERE id=?", why, JSON.stringify({ c, n, by: me.id, t: Date.now() }), late, b.id);
    if (late) await run('UPDATE users SET late=late+1 WHERE id=?', b.u);
    await log('returned', b.id, `Condition: ${c}. ${n}. ${why}${late ? ' Late return.' : ''}`, me.id);
    if (worse) await Promise.all([r.o, r.m].map(u => note(u, `${r.n}: condition changed on return`)));
  },
  async inc(me, p) {
    const b = await B(p.id), r = await R(b.r); if (!(canR(me, r) || b.u === me.id)) bad('Not allowed', 403); if (!['checkedout', 'returned'].includes(b.st)) bad('Incidents attach to a used booking');
    const t = oneOf(p.t, INC_T, 'type'), s = oneOf(p.s, SEV, 'severity'), d = str(p.d, 500); if (!d) bad('Describe what happened');
    const id = await nextId('I'); await run("INSERT INTO inc(id,b,t,s,d,st,rep,at) VALUES(?,?,?,?,?,'open',?,?)", id, b.id, t, s, d, me.id, Date.now());
    await log('incident', b.id, `${t} (${s}): ${d}`, me.id); await Promise.all([r.o, r.m, b.u].filter(u => u !== me.id).map(u => note(u, `Incident reported on ${r.n}: ${t}`)));
  },
  async resolve(me, p) {
    const n = (await one('SELECT * FROM inc WHERE id=?', p.id)) || bad('Incident not found', 404), b = await B(n.b), r = await R(b.r);
    if (!canR(me, r)) bad('Only the owner, manager or admin can decide incidents', 403); if (n.st !== 'open') bad('Already decided');
    const o = oneOf(p.o, OUT, 'outcome'), w = str(p.w); if (!w) bad('Reasoning is required');
    const res = `${o}. ${w} (${me.name})`; await run("UPDATE inc SET st='resolved',res=? WHERE id=?", res, n.id);
    await log('incident-' + o.split(':')[0].toLowerCase(), b.id, res, me.id); await note(n.rep, 'Incident decided: ' + o);
  },
  async credreq(me, p) {
    if (me.role !== 'user') bad('Only students hold credentials'); const k = oneOf(p.k, Object.keys(CRED), 'credential');
    if ((await credOf(me.id))[k] === 'verified') bad('Already verified');
    await run("INSERT INTO creds(u,k,st) VALUES(?,?,'pending') ON CONFLICT(u,k) DO UPDATE SET st='pending'", me.id, k); await log('credential-submitted', me.id, CRED[k], me.id);
  },
  async credok(me, p) {
    if (!['manager', 'admin'].includes(me.role)) bad('Not allowed', 403); const k = oneOf(p.k, Object.keys(CRED), 'credential');
    if ((await credOf(p.u))[k] !== 'pending') bad('Nothing pending');
    await run("UPDATE creds SET st='verified' WHERE u=? AND k=?", p.u, k); await log('credential-verified', p.u, CRED[k], me.id); await note(p.u, CRED[k] + ' verified');
  },
  async credno(me, p) {
    if (!['manager', 'admin'].includes(me.role)) bad('Not allowed', 403); const k = oneOf(p.k, Object.keys(CRED), 'credential');
    if ((await credOf(p.u))[k] !== 'pending') bad('Nothing pending');
    await run('DELETE FROM creds WHERE u=? AND k=?', p.u, k); await log('credential-rejected', p.u, CRED[k], me.id); await note(p.u, CRED[k] + ' was not verified');
  },
  async vown(me, p) {
    if (me.role !== 'admin') bad('Not allowed', 403); const u = (await one("SELECT * FROM users WHERE id=? AND role='owner'", p.u)) || bad('Owner not found', 404);
    await run('UPDATE users SET verified=1 WHERE id=?', u.id); await log('owner-verified', u.id, 'Verified by admin', me.id); await note(u.id, 'You can now list resources');
  },
  async newres(me, p) {
    if (me.role !== 'owner' || !me.verified) bad('Only verified owners can list resources', 403);
    const n = str(p.n, 80), l = str(p.l, 80), rule = str(p.rule, 400); if (!n || !l || !rule) bad('Name, location and rules are required');
    const req = (Array.isArray(p.req) ? p.req : []).filter(k => CRED[k]), mgr = await one("SELECT id FROM users WHERE role='manager' LIMIT 1");
    const id = await nextId('r'); await run('INSERT INTO res(id,n,c,l,o,m,req,mode,q,rule) VALUES(?,?,?,?,?,?,?,?,?,?)', id, n, oneOf(p.c, CATS, 'category'), l, me.id, mgr.id, JSON.stringify(req), oneOf(p.m, ['auto', 'manual'], 'approval mode'), Math.min(40, Math.max(1, +p.q || 4)), rule);
    await log('listed', id, n, me.id);
  },
  async readnotif(me) { await run('UPDATE notif SET seen=1 WHERE u=?', me.id); },
  async reset(me) { if (me.role !== 'admin') bad('Not allowed', 403); await seed(true); }
};

// ---------- state snapshot (filtered per role) ----------
async function stateFor(me) {
  await tick();
  const rawRes = await all('SELECT * FROM res WHERE active=1');
  const rs = await Promise.all(rawRes.map(async r => {
    const wl = await one("SELECT COUNT(*) v FROM bk WHERE r=? AND st='waitlisted'", r.id);
    return { ...r, req: JSON.parse(r.req), wl: wl.v };
  }));
  const can = r => canR(me, r);
  const allBk = await all('SELECT * FROM bk ORDER BY t DESC');
  const bkFiltered = [];
  for (const b of allBk) {
    const matches = me.role === 'user' ? b.u === me.id : can(rs.find(r => r.id === b.r) || (await R(b.r)));
    if (matches) bkFiltered.push(b);
  }
  const ids = new Set(bkFiltered.map(b => b.id));
  const waitlisted = await all("SELECT * FROM bk WHERE st='waitlisted'");
  const bk = await Promise.all(bkFiltered.map(async b => {
    let pos = 0;
    if (b.st === 'waitlisted') {
      const rList = waitlisted.filter(x => x.r === b.r);
      const scored = await Promise.all(rList.map(async x => ({ x, s: await score(x.u) })));
      scored.sort((a, c) => a.s - c.s || a.x.t - c.x.t);
      pos = scored.findIndex(x => x.x.id === b.id) + 1;
    }
    return { ...b, ci: b.ci && JSON.parse(b.ci), co: b.co && JSON.parse(b.co), pos };
  }));
  const inc = (await all('SELECT * FROM inc ORDER BY at DESC')).filter(n => ids.has(n.b));
  const rawAudit = await all('SELECT * FROM audit ORDER BY id');
  const audit = me.role === 'admin' ? rawAudit : rawAudit.filter(e => ids.has(e.ent));
  const rawUsers = await all('SELECT id,name,role,verified,late,noshow FROM users');
  const users = await Promise.all(rawUsers.map(async u => ({ ...u, score: u.role === 'user' ? await score(u.id) : 0 })));
  const reviewer = ['manager', 'admin'].includes(me.role);
  const userCreds = await credOf(me.id);
  const slots = await all(`SELECT r,day,s,h,st FROM bk WHERE st IN ${ACT} AND day>=?`, localDay());
  const notifs = await all('SELECT * FROM notif WHERE u=? ORDER BY id DESC LIMIT 50', me.id);
  const pend = reviewer ? await all("SELECT u,k FROM creds WHERE st='pending'") : [];
  return {
    me: { ...users.find(u => u.id === me.id), creds: userCreds },
    users: me.role === 'user' ? users.filter(u => u.id === me.id || rs.some(r => r.o === u.id || r.m === u.id)) : users,
    res: rs, slots, bk, inc, audit, notif: notifs, pend
  };
}

// ---------- seed ----------
async function seed(force) {
  if (!force) {
    try {
      const u = await one('SELECT COUNT(*) v FROM users');
      if (u && u.v) return;
    } catch {}
  }
  for (const t of ['users', 'creds', 'res', 'bk', 'inc', 'notif', 'audit', 'sess', 'meta']) await run('DELETE FROM ' + t);
  const pw = hashPw(process.env.DEMO_PASSWORD || 'demo1234');
  const us = [
    ['u1', 'Asha Rao (student)', 'student@demo', 'user', 1],
    ['u2', 'Ravi Menon (student)', 'student2@demo', 'user', 1],
    ['u3', 'Dr. Mehta (owner)', 'owner@demo', 'owner', 1],
    ['u4', 'Imran (lab manager)', 'manager@demo', 'manager', 1],
    ['u5', 'Priya (admin)', 'admin@demo', 'admin', 1],
    ['u6', 'Dr. Rao (new owner)', 'owner2@demo', 'owner', 0]
  ];
  for (const u of us) await run('INSERT INTO users(id,name,email,role,pw,verified) VALUES(?,?,?,?,?,?)', ...u.slice(0, 4), pw, u[4]);
  await run('UPDATE users SET late=1,noshow=1 WHERE id=?', 'u2');
  for (const c of [['u1', 'safety'], ['u1', 'electronics'], ['u2', 'safety']]) await run("INSERT INTO creds VALUES(?,?, 'verified')", ...c);
  const rs = [
    ['r1', '3D Printer (Prusa MK4)', 'Makerspace', 'Block B, room 12', ['safety'], 'manual', 6, 'Max 6 h per user per week. Remove prints within 30 min of finishing.'],
    ['r2', 'Digital Oscilloscope 200 MHz', 'Electronics', 'Block A, room 204', ['electronics'], 'auto', 8, 'Use ESD wrist strap. Probes stay in the case.'],
    ['r3', 'GPU Workstation (RTX 4090)', 'Computing', 'Block C, room 101', [], 'auto', 10, 'No crypto mining. Save work to your own storage.'],
    ['r4', 'CNC Router', 'Makerspace', 'Block B, room 14', ['safety', 'cnc'], 'manual', 4, 'Supervisor must be present. Never auto-approved.'],
    ['r5', 'Seminar Room 3', 'Rooms', 'Admin block, floor 2', [], 'auto', 6, 'Leave the room as found. Max 20 people.'],
    ['r6', 'DSLR and Lighting Kit', 'Media', 'Media studio', [], 'manual', 6, 'Return batteries charged. Lenses stay capped.']
  ];
  for (const r of rs) await run('INSERT INTO res(id,n,c,l,o,m,req,mode,q,rule) VALUES(?,?,?,?,?,?,?,?,?,?)', r[0], r[1], r[2], r[3], 'u3', 'u4', JSON.stringify(r[4]), r[5], r[6], r[7]);
  await run("INSERT INTO bk(id,r,u,day,s,h,purpose,st,why,t) VALUES('B1','r1','u2',?,10,5,'Robot chassis parts','approved','Approved by Dr. Mehta (owner)',1)", localDay(1));
  await run("INSERT INTO bk(id,r,u,day,s,h,purpose,st,why,t,ci) VALUES('B2','r2','u1',?,9,2,'Amplifier lab','checkedout','In use since check-in',2,?)", localDay(-1), JSON.stringify({ c: 'Good', n: 'Probes present', by: 'u1', t: Date.now() }));
  await run("INSERT INTO meta VALUES('seq',100)");
  await log('listed', 'r1', 'Seed data', 'u3');
  await log('approved', 'B1', 'Approved by Dr. Mehta (owner)', 'u3');
  await log('checked-in', 'B2', 'Condition: Good. Probes present', 'u1');
}

// ---------- HTTP ----------
const send = (res, c, o) => { res.writeHead(c, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }); res.end(JSON.stringify(o)); };
const body = req => new Promise((ok, no) => { let d = ''; req.on('data', c => { d += c; if (d.length > 2e4) { no(Object.assign(new Error('Payload too large'), { code: 413 })); req.destroy(); } }); req.on('end', () => { try { ok(d ? JSON.parse(d) : {}); } catch { no(Object.assign(new Error('Invalid JSON'), { code: 400 })); } }); });
const authed = async req => {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  const s = t && (await one('SELECT * FROM sess WHERE tok=? AND exp>?', t, Date.now()));
  return s ? await one('SELECT * FROM users WHERE id=?', s.u) : null;
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    if (url.pathname === '/' || url.pathname === '/index.html') {
      const p = path.join(__dirname, 'public', 'index.html');
      if (fs.existsSync(p)) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
        return res.end(fs.readFileSync(p));
      }
    }
    if (!url.pathname.startsWith('/api/')) return send(res, 404, { error: 'Not found' });
    await ensureInit();
    if (url.pathname === '/api/login' && req.method === 'POST') {
      if (limited(req.socket.remoteAddress)) return send(res, 429, { error: 'Too many attempts. Wait a minute.' });
      const b = await body(req), u = await one('SELECT * FROM users WHERE email=?', str(b.email, 100));
      if (!u || !checkPw(String(b.password || ''), u.pw)) return send(res, 401, { error: 'Wrong email or password' });
      const tok = crypto.randomBytes(32).toString('hex');
      await run('INSERT INTO sess VALUES(?,?,?)', tok, u.id, Date.now() + 12 * 36e5);
      return send(res, 200, { token: tok });
    }
    const me = await authed(req);
    if (!me) return send(res, 401, { error: 'Sign in required' });
    if (url.pathname === '/api/logout') {
      await run('DELETE FROM sess WHERE tok=?', req.headers.authorization.replace('Bearer ', ''));
      return send(res, 200, {});
    }
    if (url.pathname === '/api/state') return send(res, 200, await stateFor(me));
    if (url.pathname === '/api/precheck') {
      const r = await R(url.searchParams.get('r'));
      return send(res, 200, await pre(me.id, r, url.searchParams.get('day') || '', +url.searchParams.get('s'), +url.searchParams.get('h')));
    }
    if (url.pathname === '/api/verify') {
      if (me.role !== 'admin') return send(res, 403, { error: 'Not allowed' });
      return send(res, 200, await verifyChain());
    }
    if (url.pathname === '/api/act' && req.method === 'POST') {
      const b = await body(req), f = ACTS[b.a];
      if (!f) return send(res, 400, { error: 'Unknown action' });
      const out = (await withTx(() => f(me, b))) || {};
      return send(res, 200, out);
    }
    send(res, 404, { error: 'Not found' });
  } catch (e) {
    send(res, e.code >= 400 && e.code < 600 ? e.code : 500, { error: e.message || 'Server error' });
    if (!e.code) console.error(e);
  }
});

if (!isServerless) {
  const ticker = setInterval(() => { tick().catch(console.error); }, 6e4);
  if (ticker.unref) ticker.unref();
}

server.server = server;
if (require.main === module) server.listen(PORT, () => console.log(`ShareLab running on http://localhost:${PORT}`));
module.exports = server;
