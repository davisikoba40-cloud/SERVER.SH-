
#!/usr/bin/env python3
"""Mobilearn backend — Flask + SQLite. Adds banners for admin ads."""
import os, re, sqlite3, uuid, time, hashlib, secrets
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, send_file
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, 'mobilearn.db')
PORT     = int(os.environ.get('PORT', 7860))
SESSION_TTL_SECONDS = 60 * 60 * 24 * 30
WITHDRAW_MIN = 20000
REFERRAL_BONUS = 450
REFERRAL_PREFIX = "try your luck — don't retreat, signup now!!!"
ONLINE_WINDOW = 90

app = Flask(__name__, static_folder=None)

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def _col_exists(conn, table, column):
    return any(r['name'] == column for r in conn.execute(f"PRAGMA table_info({table})").fetchall())

def _hash(pw):
    return generate_password_hash(pw, method='pbkdf2:sha256', salt_length=16)

def _verify_and_upgrade(conn, table, ident_col, ident_val, plain_pw):
    row = conn.execute(f"SELECT * FROM {table} WHERE {ident_col}=?", (ident_val,)).fetchone()
    if not row: return None
    algo = row['pw_algo'] if 'pw_algo' in row.keys() else 'sha256'
    if algo == 'pbkdf2':
        ok = check_password_hash(row['password'], plain_pw)
    else:
        ok = hashlib.sha256(plain_pw.encode()).hexdigest() == row['password']
    if not ok: return None
    if algo == 'sha256':
        if table == 'users':
            conn.execute("UPDATE users SET password=?, pw_algo='pbkdf2' WHERE id=?", (_hash(plain_pw), row['id']))
        else:
            conn.execute("UPDATE admins SET password=?, pw_algo='pbkdf2', updated_at=? WHERE username=?", (_hash(plain_pw), time.time(), row['username']))
        conn.commit()
    return row

def _gen_ref_code(conn):
    for _ in range(20):
        code = secrets.token_hex(4).upper()
        if not conn.execute("SELECT 1 FROM users WHERE referral_code=?", (code,)).fetchone():
            return code
    return secrets.token_hex(6).upper()

def init_db():
    conn = get_db(); c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, phone TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            balance REAL NOT NULL DEFAULT 0, verified INTEGER NOT NULL DEFAULT 0,
            note TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, last_login REAL,
            pw_algo TEXT NOT NULL DEFAULT 'sha256',
            referral_code TEXT, referred_by TEXT,
            referral_credited INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS admins (
            username TEXT PRIMARY KEY, password TEXT NOT NULL,
            pw_algo TEXT NOT NULL DEFAULT 'sha256', updated_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS videos (
            id TEXT PRIMARY KEY, video_id TEXT NOT NULL, title TEXT NOT NULL,
            reward REAL NOT NULL, published INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS merchant_ids (
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, merchant_id TEXT NOT NULL,
            submitted_at REAL NOT NULL, updated_at REAL);
        CREATE TABLE IF NOT EXISTS credit_log (
            id TEXT PRIMARY KEY, username TEXT NOT NULL, video_id TEXT NOT NULL,
            reward REAL NOT NULL, credited_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            created_at REAL NOT NULL, expires_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
            target TEXT, payload TEXT, created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY, from_username TEXT NOT NULL, to_username TEXT NOT NULL,
            body TEXT NOT NULL, created_at REAL NOT NULL, read_at REAL);
        CREATE TABLE IF NOT EXISTS announcements (
            id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL,
            created_by TEXT NOT NULL, created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS announcement_reads (
            username TEXT NOT NULL, announcement_id TEXT NOT NULL,
            read_at REAL NOT NULL, PRIMARY KEY (username, announcement_id));
        CREATE TABLE IF NOT EXISTS deal_requests (
            id TEXT PRIMARY KEY, username TEXT NOT NULL, kind TEXT NOT NULL,
            message TEXT NOT NULL, video_id TEXT, status TEXT NOT NULL DEFAULT 'pending',
            admin_note TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, resolved_at REAL);
        CREATE TABLE IF NOT EXISTS withdrawals (
            id TEXT PRIMARY KEY, username TEXT NOT NULL, amount REAL NOT NULL,
            merchant_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            admin_note TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, resolved_at REAL);
        CREATE TABLE IF NOT EXISTS banners (
            id TEXT PRIMARY KEY, image_url TEXT NOT NULL,
            link_url TEXT NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL);
    ''')
    for tbl, col, ddl in [
        ('sessions','expires_at',"ALTER TABLE sessions ADD COLUMN expires_at REAL"),
        ('users','pw_algo',"ALTER TABLE users ADD COLUMN pw_algo TEXT NOT NULL DEFAULT 'sha256'"),
        ('admins','pw_algo',"ALTER TABLE admins ADD COLUMN pw_algo TEXT NOT NULL DEFAULT 'sha256'"),
        ('admins','updated_at',"ALTER TABLE admins ADD COLUMN updated_at REAL NOT NULL DEFAULT 0"),
        ('users','referral_code',"ALTER TABLE users ADD COLUMN referral_code TEXT"),
        ('users','referred_by',"ALTER TABLE users ADD COLUMN referred_by TEXT"),
        ('users','referral_credited',"ALTER TABLE users ADD COLUMN referral_credited INTEGER NOT NULL DEFAULT 0"),
        ('users','last_seen',"ALTER TABLE users ADD COLUMN last_seen REAL"),
    ]:
        if not _col_exists(conn, tbl, col):
            c.execute(ddl)
    c.execute("UPDATE sessions SET expires_at=? WHERE expires_at IS NULL",
              (time.time() + SESSION_TTL_SECONDS,))
    for row in c.execute("SELECT id FROM users WHERE referral_code IS NULL OR referral_code=''").fetchall():
        c.execute("UPDATE users SET referral_code=? WHERE id=?", (_gen_ref_code(conn), row['id']))
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_refcode ON users(referral_code)")
    if not c.execute("SELECT 1 FROM admins WHERE username='admin'").fetchone():
        c.execute("INSERT INTO admins (username, password, pw_algo, updated_at) VALUES (?,?,?,?)",
                  ('admin', _hash('mobilearn2025'), 'pbkdf2', time.time()))
    if not c.execute("SELECT 1 FROM users WHERE username='amara'").fetchone():
        c.execute("""INSERT INTO users (id, username, phone, password, status, balance,
            verified, note, created_at, pw_algo, referral_code) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            ('u-demo', 'amara', '0701234567', _hash('amara123'), 'active', 0, 0, '', time.time(), 'pbkdf2', _gen_ref_code(conn)))
    if not c.execute("SELECT 1 FROM videos WHERE id='v-seed'").fetchone():
        c.execute("""INSERT INTO videos (id, video_id, title, reward, published, created_at)
            VALUES (?,?,?,?,?,?)""",
            ('v-seed', 'AWOXpzQzkp8', 'Sponsored video — watch to the end', 1900, 1, time.time()))
    conn.commit(); conn.close()

def _audit(conn, actor, action, target=None, payload=None):
    conn.execute("INSERT INTO audit_log (id, actor, action, target, payload, created_at) VALUES (?,?,?,?,?,?)",
                 ('a' + uuid.uuid4().hex[:12], actor, action, target, payload, time.time()))

def _msg(conn, to_username, body, from_username='admin'):
    conn.execute("INSERT INTO messages (id, from_username, to_username, body, created_at) VALUES (?,?,?,?,?)",
                 ('msg' + uuid.uuid4().hex[:12], from_username, to_username, body, time.time()))

def _create_session(conn, user_id):
    token = secrets.token_urlsafe(32)
    now = time.time()
    conn.execute("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
                 (token, user_id, now, now + SESSION_TTL_SECONDS))
    return token

def _bearer_token():
    a = request.headers.get('Authorization', '')
    return a[7:].strip() or None if a.startswith('Bearer ') else None

def _current_user():
    tok = _bearer_token()
    if not tok: return None
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM sessions WHERE token=?", (tok,)).fetchone()
        if not row: return None
        if row['expires_at'] and row['expires_at'] < time.time():
            conn.execute("DELETE FROM sessions WHERE token=?", (tok,)); conn.commit(); return None
        if row['user_id'] == '__admin__': return {'is_admin': True, 'username': 'admin'}
        u = conn.execute("SELECT * FROM users WHERE id=?", (row['user_id'],)).fetchone()
        return dict(u) if u else None
    finally:
        conn.close()

def require_member(fn):
    @wraps(fn)
    def w(*a, **kw):
        u = _current_user()
        if not u or u.get('is_admin'): return jsonify({'error': 'Unauthorized'}), 401
        if u['status'] != 'active': return jsonify({'error': 'Account not active.'}), 403
        return fn(*a, **kw)
    return w

def require_admin(fn):
    @wraps(fn)
    def w(*a, **kw):
        u = _current_user()
        if not u or not u.get('is_admin'): return jsonify({'error': 'Unauthorized'}), 401
        return fn(*a, **kw)
    return w

def _unread_count(conn, username):
    msg = conn.execute("SELECT COUNT(*) FROM messages WHERE to_username=? AND from_username='admin' AND read_at IS NULL",
                       (username,)).fetchone()[0]
    ann = conn.execute("""SELECT COUNT(*) FROM announcements a
        WHERE NOT EXISTS (SELECT 1 FROM announcement_reads r
                          WHERE r.username=? AND r.announcement_id=a.id)""",
                       (username,)).fetchone()[0]
    return msg + ann

@app.after_request
def no_cache(resp):
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    return resp

@app.route('/')
def index(): return send_from_directory(BASE_DIR, 'index.html')

PHONE_RE = re.compile(r'^(\+?256|0)(70|74|75|76)\d{7}$')
_clean = lambda p: re.sub(r'[\s\-()]', '', (p or '').strip())

@app.post('/api/signup')
def signup():
    d = request.get_json() or {}
    username = (d.get('username') or '').strip()
    phone = _clean(d.get('phone'))
    password = d.get('password') or ''
    ref_code = (d.get('ref') or '').strip().upper()
    if len(username) < 3: return jsonify({'error': 'Username must be at least 3 characters.'}), 400
    if not PHONE_RE.match(phone): return jsonify({'error': 'Airtel Uganda numbers only (070/074/075/076 + 7 digits).'}), 400
    if len(password) < 6: return jsonify({'error': 'Password must be at least 6 characters.'}), 400
    conn = get_db(); c = conn.cursor()
    try:
        if c.execute("SELECT 1 FROM users WHERE lower(username)=?", (username.lower(),)).fetchone():
            return jsonify({'error': 'Username already taken.'}), 409
        if c.execute("SELECT 1 FROM users WHERE phone=?", (phone,)).fetchone():
            return jsonify({'error': 'Airtel number already registered.'}), 409
        referred_by = None
        if ref_code:
            ref_user = c.execute("SELECT username FROM users WHERE referral_code=?", (ref_code,)).fetchone()
            if ref_user: referred_by = ref_user['username']
        uid = 'u' + uuid.uuid4().hex[:12]
        rcode = _gen_ref_code(conn)
        c.execute("""INSERT INTO users (id, username, phone, password, status, balance,
            verified, note, created_at, pw_algo, referral_code, referred_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (uid, username, phone, _hash(password), 'pending', 0, 0, '', time.time(),
             'pbkdf2', rcode, referred_by))
        _audit(conn, username, 'signup', target=uid,
               payload=('referred_by=' + referred_by) if referred_by else None)
        conn.commit()
        extra = ""
        if referred_by:
            extra = f" You were referred by {referred_by} — once approved, they earn UGX {REFERRAL_BONUS}."
        return jsonify({'message': 'Account created! Pending admin approval. '
                                   'Pay UGX 19,500 via *185*9# → 7285061 (MOBILE LABS), then submit '
                                   'your activation request in the Inbox.' + extra,
                        'referral_code': rcode}), 201
    finally:
        conn.close()

@app.post('/api/login')
def login():
    d = request.get_json() or {}
    ident = (d.get('identifier') or '').strip()
    pw = d.get('password') or ''
    if not ident or not pw: return jsonify({'error': 'Enter username/number and password.'}), 400
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE lower(username)=? OR phone=?", (ident.lower(), _clean(ident))).fetchone()
        if not row: return jsonify({'error': 'No account found.'}), 404
        matched = _verify_and_upgrade(conn, 'users', 'id', row['id'], pw)
        if not matched: return jsonify({'error': 'Incorrect password.'}), 401
        if matched['status'] == 'pending': return jsonify({'error': 'Account pending admin approval.'}), 403
        if matched['status'] == 'suspended': return jsonify({'error': 'Account suspended. Contact support.'}), 403
        if matched['status'] == 'blocked': return jsonify({'error': 'Account blocked. Contact support.'}), 403
        tok = _create_session(conn, matched['id'])
        now = time.time()
        conn.execute("UPDATE users SET last_login=?, last_seen=? WHERE id=?", (now, now, matched['id']))
        conn.commit()
        unread = _unread_count(conn, matched['username'])
        return jsonify({'token': tok, 'unread': unread, 'user': {
            'id': matched['id'], 'username': matched['username'], 'phone': matched['phone'],
            'balance': matched['balance'], 'verified': bool(matched['verified']),
            'status': matched['status'], 'referral_code': matched['referral_code'] or ''}})
    finally:
        conn.close()

@app.get('/api/me')
def me():
    u = _current_user()
    if not u: return jsonify({'error': 'Unauthorized'}), 401
    if u.get('is_admin'): return jsonify({'is_admin': True})
    conn = get_db()
    try:
        now = time.time()
        conn.execute("UPDATE users SET last_seen=? WHERE id=?", (now, u['id']))
        conn.commit()
        return jsonify({'id': u['id'], 'username': u['username'], 'phone': u['phone'],
                        'balance': u['balance'], 'verified': bool(u['verified']),
                        'status': u['status'], 'unread': _unread_count(conn, u['username']),
                        'referral_code': u.get('referral_code') or '',
                        'last_seen': now})
    finally:
        conn.close()

@app.post('/api/logout')
def logout():
    tok = _bearer_token()
    if tok:
        conn = get_db(); conn.execute("DELETE FROM sessions WHERE token=?", (tok,)); conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.post('/api/change-password')
@require_member
def change_password():
    d = request.get_json() or {}
    cur = d.get('current_password') or ''
    nw = d.get('new_password') or ''
    if len(nw) < 6: return jsonify({'error': 'New password must be at least 6 characters.'}), 400
    if cur == nw: return jsonify({'error': 'New password must differ from current.'}), 400
    conn = get_db()
    try:
        uid = _current_user()['id']
        m = _verify_and_upgrade(conn, 'users', 'id', uid, cur)
        if not m: return jsonify({'error': 'Current password is incorrect.'}), 401
        conn.execute("UPDATE users SET password=?, pw_algo='pbkdf2' WHERE id=?", (_hash(nw), uid))
        keep = _bearer_token()
        conn.execute("DELETE FROM sessions WHERE user_id=? AND token<>?", (uid, keep))
        _audit(conn, m['username'], 'change-password', target=uid)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.get('/api/videos')
@require_member
def list_videos():
    conn = get_db()
    rows = conn.execute("SELECT * FROM videos WHERE published=1 ORDER BY created_at DESC").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.get('/api/credits')
@require_member
def my_credits():
    conn = get_db()
    rows = conn.execute("SELECT video_id FROM credit_log WHERE username=?", (_current_user()['username'],)).fetchall()
    conn.close(); return jsonify([r['video_id'] for r in rows])

@app.post('/api/credit')
@require_member
def credit():
    u = _current_user()
    vid = (request.get_json() or {}).get('video_id')
    if not vid: return jsonify({'error': 'Missing video_id'}), 400
    conn = get_db()
    try:
        video = conn.execute("SELECT * FROM videos WHERE id=?", (vid,)).fetchone()
        if not video: return jsonify({'error': 'Video not found'}), 404
        if conn.execute("SELECT 1 FROM credit_log WHERE username=? AND video_id=?", (u['username'], vid)).fetchone():
            return jsonify({'error': 'Already earned from this video.', 'balance': u['balance']}), 409
        reward = video['reward']
        conn.execute("UPDATE users SET balance=balance+?, verified=0 WHERE id=?", (reward, u['id']))
        conn.execute("INSERT INTO credit_log (id, username, video_id, reward, credited_at) VALUES (?,?,?,?,?)",
                     ('c' + uuid.uuid4().hex[:12], u['username'], vid, reward, time.time()))
        conn.commit()
        nb = conn.execute("SELECT balance FROM users WHERE id=?", (u['id'],)).fetchone()['balance']
        return jsonify({'ok': True, 'reward': reward, 'balance': nb})
    finally:
        conn.close()

@app.get('/api/merchant')
@require_member
def get_merchant():
    conn = get_db()
    row = conn.execute("SELECT merchant_id FROM merchant_ids WHERE username=?", (_current_user()['username'],)).fetchone()
    conn.close(); return jsonify({'merchant_id': row['merchant_id'] if row else ''})

@app.post('/api/merchant')
@require_member
def submit_merchant():
    u = _current_user()
    mid = _clean((request.get_json() or {}).get('merchant_id'))
    if not PHONE_RE.match(mid): return jsonify({'error': 'Invalid Airtel number (e.g. 0701234567).'}), 400
    conn = get_db()
    try:
        now = time.time()
        if conn.execute("SELECT 1 FROM merchant_ids WHERE username=?", (u['username'],)).fetchone():
            conn.execute("UPDATE merchant_ids SET merchant_id=?, updated_at=? WHERE username=?", (mid, now, u['username']))
        else:
            conn.execute("INSERT INTO merchant_ids (id, username, merchant_id, submitted_at) VALUES (?,?,?,?)",
                         ('m' + uuid.uuid4().hex[:12], u['username'], mid, now))
        _audit(conn, u['username'], 'merchant-submit', payload=mid)
        conn.commit(); return jsonify({'ok': True, 'merchant_id': mid})
    finally:
        conn.close()

@app.get('/api/withdrawals')
@require_member
def my_withdrawals():
    u = _current_user()
    conn = get_db()
    try:
        merchant = conn.execute("SELECT merchant_id FROM merchant_ids WHERE username=?", (u['username'],)).fetchone()
        merchant_id = merchant['merchant_id'] if merchant else ''
        pending = conn.execute("SELECT COUNT(*) FROM withdrawals WHERE username=? AND status='pending'", (u['username'],)).fetchone()[0]
        rows = conn.execute("""SELECT * FROM withdrawals WHERE username=?
            ORDER BY created_at DESC LIMIT 30""", (u['username'],)).fetchall()
        return jsonify({
            'balance': u['balance'], 'merchant_id': merchant_id, 'min': WITHDRAW_MIN,
            'has_pending': pending > 0, 'withdrawals': [dict(r) for r in rows],
        })
    finally:
        conn.close()

@app.post('/api/withdraw')
@require_member
def request_withdrawal():
    u = _current_user()
    d = request.get_json() or {}
    try: amount = float(d.get('amount') or 0)
    except (TypeError, ValueError): return jsonify({'error': 'Invalid amount.'}), 400
    if amount < WITHDRAW_MIN:
        return jsonify({'error': f'Minimum withdrawal is UGX {WITHDRAW_MIN:,}.'}), 400
    conn = get_db()
    try:
        merchant = conn.execute("SELECT merchant_id FROM merchant_ids WHERE username=?", (u['username'],)).fetchone()
        if not merchant or not merchant['merchant_id']:
            return jsonify({'error': 'Save your Airtel merchant ID first (Payout details).'}), 400
        merchant_id = merchant['merchant_id']
        if conn.execute("SELECT 1 FROM withdrawals WHERE username=? AND status='pending'", (u['username'],)).fetchone():
            return jsonify({'error': 'You already have a pending withdrawal. Please wait for admin approval.'}), 400
        fresh = conn.execute("SELECT balance FROM users WHERE id=?", (u['id'],)).fetchone()
        if (fresh['balance'] or 0) < amount:
            return jsonify({'error': 'Insufficient balance.'}), 400
        wid = 'w' + uuid.uuid4().hex[:12]
        conn.execute("INSERT INTO withdrawals (id, username, amount, merchant_id, status, created_at) VALUES (?,?,?,?,?,?)",
                     (wid, u['username'], amount, merchant_id, 'pending', time.time()))
        msg_body = (f"Withdrawal request of UGX {amount:,.0f} to {merchant_id} received. "
                    "Please allow up to 2 hours for admin to approve and confirm your payment. Be patient.")
        _msg(conn, u['username'], msg_body)
        _audit(conn, u['username'], 'withdraw-request', target=wid, payload=f'{amount} → {merchant_id}')
        conn.commit()
        return jsonify({'ok': True, 'id': wid, 'message': msg_body}), 201
    finally:
        conn.close()

@app.get('/api/referrals')
@require_member
def my_referrals():
    u = _current_user()
    conn = get_db()
    try:
        rows = conn.execute("""SELECT username, status, referral_credited, created_at
            FROM users WHERE referred_by=? ORDER BY created_at DESC""", (u['username'],)).fetchall()
        total = len(rows)
        credited = sum(1 for r in rows if r['referral_credited'])
        return jsonify({
            'code': u.get('referral_code') or '', 'bonus': REFERRAL_BONUS, 'prefix': REFERRAL_PREFIX,
            'referred_total': total, 'credited_total': credited,
            'earned': credited * REFERRAL_BONUS, 'referrals': [dict(r) for r in rows],
        })
    finally:
        conn.close()

@app.get('/api/inbox')
@require_member
def inbox():
    u = _current_user()
    conn = get_db()
    try:
        ann = conn.execute("""SELECT a.*, CASE WHEN r.read_at IS NULL THEN 0 ELSE 1 END AS is_read
            FROM announcements a
            LEFT JOIN announcement_reads r ON r.announcement_id=a.id AND r.username=?
            ORDER BY a.created_at DESC LIMIT 50""", (u['username'],)).fetchall()
        msgs = conn.execute("""SELECT id, from_username, to_username, body, created_at, read_at
            FROM messages WHERE from_username=? OR to_username=?
            ORDER BY created_at ASC LIMIT 200""", (u['username'], u['username'])).fetchall()
        reqs = conn.execute("""SELECT id, kind, message, video_id, status, admin_note, created_at, resolved_at
            FROM deal_requests WHERE username=? ORDER BY created_at DESC LIMIT 50""", (u['username'],)).fetchall()
        return jsonify({'announcements': [dict(r) for r in ann],
                        'messages': [dict(r) for r in msgs],
                        'deal_requests': [dict(r) for r in reqs],
                        'unread': _unread_count(conn, u['username'])})
    finally:
        conn.close()

@app.post('/api/inbox/message')
@require_member
def inbox_send():
    u = _current_user()
    body = ((request.get_json() or {}).get('body') or '').strip()
    if not body: return jsonify({'error': 'Message is empty.'}), 400
    if len(body) > 4000: return jsonify({'error': 'Message too long.'}), 400
    conn = get_db()
    try:
        conn.execute("INSERT INTO messages (id, from_username, to_username, body, created_at) VALUES (?,?,?,?,?)",
                     ('msg' + uuid.uuid4().hex[:12], u['username'], 'admin', body, time.time()))
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.post('/api/inbox/mark-read')
@require_member
def inbox_mark_read():
    u = _current_user()
    conn = get_db()
    try:
        now = time.time()
        conn.execute("UPDATE messages SET read_at=? WHERE to_username=? AND read_at IS NULL", (now, u['username']))
        for row in conn.execute("SELECT id FROM announcements").fetchall():
            conn.execute("INSERT OR IGNORE INTO announcement_reads (username, announcement_id, read_at) VALUES (?,?,?)",
                         (u['username'], row['id'], now))
        conn.commit(); return jsonify({'ok': True, 'unread': 0})
    finally:
        conn.close()

@app.post('/api/deal-request')
@require_member
def create_deal_request():
    u = _current_user()
    d = request.get_json() or {}
    kind = (d.get('kind') or '').strip()
    msg = (d.get('message') or '').strip()
    vid = (d.get('video_id') or '').strip() or None
    if kind not in ('verification', 'activation', 'payout', 'other'):
        return jsonify({'error': 'Invalid request type.'}), 400
    if len(msg) < 5: return jsonify({'error': 'Describe your request (at least 5 characters).'}), 400
    conn = get_db()
    try:
        rid = 'dr' + uuid.uuid4().hex[:12]
        conn.execute("INSERT INTO deal_requests (id, username, kind, message, video_id, status, created_at) VALUES (?,?,?,?,?,?,?)",
                     (rid, u['username'], kind, msg, vid, 'pending', time.time()))
        _audit(conn, u['username'], f'deal-{kind}', payload=msg[:200])
        conn.commit(); return jsonify({'ok': True, 'id': rid})
    finally:
        conn.close()

@app.get('/api/banners')
@require_member
def list_banners():
    conn = get_db()
    rows = conn.execute("SELECT * FROM banners WHERE active=1 ORDER BY created_at DESC LIMIT 5").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.post('/api/admin/login')
def admin_login():
    d = request.get_json() or {}
    u = (d.get('username') or '').strip()
    p = d.get('password') or ''
    conn = get_db()
    try:
        m = _verify_and_upgrade(conn, 'admins', 'username', u, p)
        if not m: return jsonify({'error': 'Invalid admin credentials.'}), 401
        tok = _create_session(conn, '__admin__')
        conn.commit(); return jsonify({'token': tok})
    finally:
        conn.close()

@app.post('/api/admin/change-password')
@require_admin
def admin_change_password():
    d = request.get_json() or {}
    cur = d.get('current_password') or ''
    nw = d.get('new_password') or ''
    if len(nw) < 8: return jsonify({'error': 'New admin password must be at least 8 characters.'}), 400
    if cur == nw: return jsonify({'error': 'New password must differ.'}), 400
    conn = get_db()
    try:
        m = _verify_and_upgrade(conn, 'admins', 'username', 'admin', cur)
        if not m: return jsonify({'error': 'Current password is incorrect.'}), 401
        conn.execute("UPDATE admins SET password=?, pw_algo='pbkdf2', updated_at=? WHERE username='admin'",
                     (_hash(nw), time.time()))
        keep = _bearer_token()
        conn.execute("DELETE FROM sessions WHERE user_id='__admin__' AND token<>?", (keep,))
        _audit(conn, 'admin', 'admin-change-password')
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.get('/api/admin/users')
@require_admin
def admin_users():
    conn = get_db()
    now = time.time()
    rows = conn.execute("""SELECT id, username, phone, status, balance, verified, note,
        created_at, last_login, last_seen, referral_code, referred_by, referral_credited
        FROM users ORDER BY created_at DESC""").fetchall()
    result = []
    for r in rows:
        d = dict(r)
        ls = d.get('last_seen')
        d['is_online'] = bool(ls and (now - ls) < ONLINE_WINDOW)
        result.append(d)
    conn.close(); return jsonify(result)

@app.post('/api/admin/users/<uid>/status')
@require_admin
def admin_user_status(uid):
    d = request.get_json() or {}
    status = d.get('status'); note = (d.get('note') or '').strip()
    if status not in ('pending', 'active', 'suspended', 'blocked'):
        return jsonify({'error': 'Invalid status'}), 400
    conn = get_db()
    try:
        target = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not target: return jsonify({'error': 'User not found.'}), 404
        conn.execute("UPDATE users SET status=?, note=? WHERE id=?", (status, note, uid))
        if status in ('suspended', 'blocked'):
            conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        if status == 'active' and target['referred_by'] and not target['referral_credited']:
            referrer = conn.execute("SELECT id, username FROM users WHERE username=?",
                                    (target['referred_by'],)).fetchone()
            if referrer:
                conn.execute("UPDATE users SET balance = balance + ? WHERE id=?",
                             (REFERRAL_BONUS, referrer['id']))
                conn.execute("UPDATE users SET referral_credited = 1 WHERE id=?", (uid,))
                _msg(conn, referrer['username'],
                     f"Referral bonus: {target['username']} was approved. "
                     f"You earned UGX {REFERRAL_BONUS:,} into your balance.")
                _audit(conn, 'admin', 'referral-credit', target=referrer['username'],
                       payload=f'{REFERRAL_BONUS} for {target["username"]}')
        _audit(conn, 'admin', f'user-{status}', target=uid, payload=note)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.delete('/api/admin/users/<uid>')
@require_admin
def admin_delete_user(uid):
    conn = get_db()
    try:
        row = conn.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
        conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        if row:
            uname = row['username']
            conn.execute("DELETE FROM merchant_ids WHERE username=?", (uname,))
            conn.execute("DELETE FROM messages WHERE from_username=? OR to_username=?", (uname, uname))
            conn.execute("DELETE FROM deal_requests WHERE username=?", (uname,))
            conn.execute("DELETE FROM withdrawals WHERE username=?", (uname,))
        _audit(conn, 'admin', 'user-delete', target=uid)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.get('/api/admin/videos')
@require_admin
def admin_videos():
    conn = get_db()
    rows = conn.execute("SELECT * FROM videos ORDER BY created_at DESC").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

YT_PATTERNS = [
    r'(?:youtube\.com\/watch\?(?:.*&)?v=)([a-zA-Z0-9_-]{11})',
    r'(?:youtu\.be\/)([a-zA-Z0-9_-]{11})',
    r'(?:youtube\.com\/embed\/)([a-zA-Z0-9_-]{11})',
    r'(?:youtube\.com\/shorts\/)([a-zA-Z0-9_-]{11})',
    r'^([a-zA-Z0-9_-]{11})$',
]

@app.post('/api/admin/videos')
@require_admin
def admin_publish_video():
    d = request.get_json() or {}
    url = (d.get('url') or '').strip()
    title = (d.get('title') or '').strip()
    try: reward = float(d.get('reward', 1900))
    except (TypeError, ValueError): return jsonify({'error': 'Reward must be a number.'}), 400
    vid = next((m.group(1) for p in YT_PATTERNS for m in [re.search(p, url)] if m), None)
    if not vid: return jsonify({'error': 'Invalid YouTube URL.'}), 400
    if not title: return jsonify({'error': 'Title required.'}), 400
    if reward <= 0: return jsonify({'error': 'Reward must be positive.'}), 400
    conn = get_db()
    try:
        conn.execute("INSERT INTO videos (id, video_id, title, reward, published, created_at) VALUES (?,?,?,?,?,?)",
                     ('v' + uuid.uuid4().hex[:12], vid, title, reward, 1, time.time()))
        _audit(conn, 'admin', 'video-publish', payload=f'{vid} · {title}')
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.delete('/api/admin/videos/<vid>')
@require_admin
def admin_delete_video(vid):
    conn = get_db()
    try:
        conn.execute("DELETE FROM videos WHERE id=?", (vid,))
        _audit(conn, 'admin', 'video-delete', target=vid)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.get('/api/admin/merchants')
@require_admin
def admin_merchants():
    conn = get_db()
    rows = conn.execute("SELECT * FROM merchant_ids ORDER BY COALESCE(updated_at, submitted_at) DESC").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.get('/api/admin/banners')
@require_admin
def admin_banners():
    conn = get_db()
    rows = conn.execute("SELECT * FROM banners ORDER BY created_at DESC").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.post('/api/admin/banners')
@require_admin
def admin_create_banner():
    d = request.get_json() or {}
    image_url = (d.get('image_url') or '').strip()
    link_url = (d.get('link_url') or '').strip()
    title = (d.get('title') or '').strip() or 'Banner'
    if not image_url: return jsonify({'error': 'Image URL required.'}), 400
    if not (image_url.startswith('http://') or image_url.startswith('https://') or image_url.startswith('data:image')):
        return jsonify({'error': 'Image URL must start with http(s):// or data:image'}), 400
    conn = get_db()
    try:
        bid = 'bn' + uuid.uuid4().hex[:12]
        conn.execute("INSERT INTO banners (id, image_url, link_url, title, active, created_at) VALUES (?,?,?,?,?,?)",
                     (bid, image_url, link_url, title, 1, time.time()))
        _audit(conn, 'admin', 'banner-create', target=bid, payload=image_url[:200])
        conn.commit(); return jsonify({'ok': True, 'id': bid})
    finally:
        conn.close()

@app.delete('/api/admin/banners/<bid>')
@require_admin
def admin_delete_banner(bid):
    conn = get_db()
    try:
        conn.execute("DELETE FROM banners WHERE id=?", (bid,))
        _audit(conn, 'admin', 'banner-delete', target=bid)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.post('/api/admin/banners/<bid>/toggle')
@require_admin
def admin_toggle_banner(bid):
    conn = get_db()
    try:
        row = conn.execute("SELECT active FROM banners WHERE id=?", (bid,)).fetchone()
        if not row: return jsonify({'error': 'Not found.'}), 404
        new_active = 0 if row['active'] else 1
        conn.execute("UPDATE banners SET active=? WHERE id=?", (new_active, bid))
        _audit(conn, 'admin', f'banner-{"activate" if new_active else "deactivate"}', target=bid)
        conn.commit()
        return jsonify({'ok': True, 'active': bool(new_active)})
    finally:
        conn.close()

@app.get('/api/admin/kpis')
@require_admin
def admin_kpis():
    conn = get_db()
    q = lambda sql, *a: conn.execute(sql, a).fetchone()[0]
    now = time.time()
    data = {
        'users': q("SELECT COUNT(*) FROM users"),
        'active': q("SELECT COUNT(*) FROM users WHERE status='active'"),
        'pending': q("SELECT COUNT(*) FROM users WHERE status='pending'"),
        'suspended': q("SELECT COUNT(*) FROM users WHERE status='suspended'"),
        'blocked': q("SELECT COUNT(*) FROM users WHERE status='blocked'"),
        'online_now': q("SELECT COUNT(*) FROM users WHERE last_seen > ?", now - ONLINE_WINDOW),
        'live_videos': q("SELECT COUNT(*) FROM videos WHERE published=1"),
        'total_videos': q("SELECT COUNT(*) FROM videos"),
        'merchants': q("SELECT COUNT(*) FROM merchant_ids"),
        'credits': q("SELECT COUNT(*) FROM credit_log"),
        'total_balance': round(q("SELECT COALESCE(SUM(balance),0) FROM users") or 0, 2),
        'pending_requests': q("SELECT COUNT(*) FROM deal_requests WHERE status='pending'"),
        'unread_msgs': q("SELECT COUNT(*) FROM messages WHERE to_username='admin' AND read_at IS NULL"),
        'pending_withdrawals': q("SELECT COUNT(*) FROM withdrawals WHERE status='pending'"),
        'total_withdrawn': round(q("SELECT COALESCE(SUM(amount),0) FROM withdrawals WHERE status='approved'") or 0, 2),
        'referrals_credited': q("SELECT COUNT(*) FROM users WHERE referral_credited=1"),
        'active_banners': q("SELECT COUNT(*) FROM banners WHERE active=1"),
    }
    conn.close(); return jsonify(data)

@app.get('/api/admin/audit')
@require_admin
def admin_audit():
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.get('/api/admin/backup')
@require_admin
def admin_backup():
    return send_file(DB_PATH, as_attachment=True, download_name=f'mobilearn-{int(time.time())}.db')

@app.get('/api/admin/withdrawals')
@require_admin
def admin_withdrawals():
    conn = get_db()
    rows = conn.execute("""SELECT w.*, u.balance AS user_balance
        FROM withdrawals w LEFT JOIN users u ON u.username=w.username
        ORDER BY COALESCE(w.resolved_at, w.created_at) DESC, w.created_at DESC""").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.post('/api/admin/withdrawals/<wid>/approve')
@require_admin
def admin_approve_withdrawal(wid):
    conn = get_db()
    try:
        w = conn.execute("SELECT * FROM withdrawals WHERE id=?", (wid,)).fetchone()
        if not w: return jsonify({'error': 'Not found.'}), 404
        if w['status'] != 'pending': return jsonify({'error': 'Already resolved.'}), 400
        user = conn.execute("SELECT * FROM users WHERE username=?", (w['username'],)).fetchone()
        if not user: return jsonify({'error': 'User not found.'}), 404
        if (user['balance'] or 0) < w['amount']:
            return jsonify({'error': 'User balance is now less than the withdrawal amount.'}), 400
        conn.execute("UPDATE users SET balance = balance - ? WHERE id=?", (w['amount'], user['id']))
        conn.execute("UPDATE withdrawals SET status='approved', resolved_at=? WHERE id=?", (time.time(), wid))
        _msg(conn, w['username'],
             f"Your withdrawal of UGX {w['amount']:,.0f} to {w['merchant_id']} has been approved. "
             "Payment will reflect on your Airtel line shortly. Thank you for using Mobilearn.")
        _audit(conn, 'admin', 'withdraw-approve', target=wid, payload=f"{w['amount']} → {w['username']}")
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.post('/api/admin/withdrawals/<wid>/reject')
@require_admin
def admin_reject_withdrawal(wid):
    note = ((request.get_json() or {}).get('admin_note') or '').strip()
    conn = get_db()
    try:
        w = conn.execute("SELECT * FROM withdrawals WHERE id=?", (wid,)).fetchone()
        if not w: return jsonify({'error': 'Not found.'}), 404
        if w['status'] != 'pending': return jsonify({'error': 'Already resolved.'}), 400
        conn.execute("UPDATE withdrawals SET status='rejected', admin_note=?, resolved_at=? WHERE id=?",
                     (note, time.time(), wid))
        _msg(conn, w['username'],
             f"Your withdrawal request of UGX {w['amount']:,.0f} was declined."
             + (f" Reason: {note}" if note else ""))
        _audit(conn, 'admin', 'withdraw-reject', target=wid, payload=note)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.get('/api/admin/conversations')
@require_admin
def admin_conversations():
    conn = get_db()
    rows = conn.execute("""
        SELECT u.username AS username, u.status AS status,
               (SELECT body FROM messages m
                  WHERE (m.from_username=u.username AND m.to_username='admin')
                     OR (m.from_username='admin' AND m.to_username=u.username)
                  ORDER BY m.created_at DESC LIMIT 1) AS last_body,
               (SELECT created_at FROM messages m
                  WHERE (m.from_username=u.username AND m.to_username='admin')
                     OR (m.from_username='admin' AND m.to_username=u.username)
                  ORDER BY m.created_at DESC LIMIT 1) AS last_at,
               (SELECT COUNT(*) FROM messages m
                  WHERE m.from_username=u.username AND m.to_username='admin' AND m.read_at IS NULL) AS unread
        FROM users u
        ORDER BY COALESCE(last_at, 0) DESC, u.username ASC""").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.get('/api/admin/messages/<username>')
@require_admin
def admin_messages(username):
    conn = get_db()
    try:
        u = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
        if not u: return jsonify({'error': 'User not found.'}), 404
        msgs = conn.execute("""SELECT id, from_username, to_username, body, created_at, read_at
            FROM messages WHERE (from_username=? AND to_username='admin')
                          OR (from_username='admin' AND to_username=?)
            ORDER BY created_at ASC""", (username, username)).fetchall()
        conn.execute("UPDATE messages SET read_at=? WHERE from_username=? AND to_username='admin' AND read_at IS NULL",
                     (time.time(), username))
        conn.commit()
        return jsonify([dict(r) for r in msgs])
    finally:
        conn.close()

@app.post('/api/admin/messages/<username>/reply')
@require_admin
def admin_reply(username):
    body = ((request.get_json() or {}).get('body') or '').strip()
    if not body: return jsonify({'error': 'Reply is empty.'}), 400
    if len(body) > 4000: return jsonify({'error': 'Reply too long.'}), 400
    conn = get_db()
    try:
        u = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
        if not u: return jsonify({'error': 'User not found.'}), 404
        conn.execute("INSERT INTO messages (id, from_username, to_username, body, created_at) VALUES (?,?,?,?,?)",
                     ('msg' + uuid.uuid4().hex[:12], 'admin', username, body, time.time()))
        _audit(conn, 'admin', 'reply', target=username, payload=body[:200])
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.get('/api/admin/announcements')
@require_admin
def admin_announcements():
    conn = get_db()
    rows = conn.execute("""SELECT a.*, 
        (SELECT COUNT(*) FROM announcement_reads r WHERE r.announcement_id=a.id) AS read_count,
        (SELECT COUNT(*) FROM users) AS total_users
        FROM announcements a ORDER BY a.created_at DESC""").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.post('/api/admin/announcements')
@require_admin
def admin_create_announcement():
    d = request.get_json() or {}
    title = (d.get('title') or '').strip()
    body = (d.get('body') or '').strip()
    if not title: return jsonify({'error': 'Title required.'}), 400
    if not body: return jsonify({'error': 'Body required.'}), 400
    if len(body) > 4000: return jsonify({'error': 'Too long.'}), 400
    conn = get_db()
    try:
        aid = 'ann' + uuid.uuid4().hex[:12]
        conn.execute("INSERT INTO announcements (id, title, body, created_by, created_at) VALUES (?,?,?,?,?)",
                     (aid, title, body, 'admin', time.time()))
        _audit(conn, 'admin', 'announce', target=aid, payload=title)
        conn.commit(); return jsonify({'ok': True, 'id': aid})
    finally:
        conn.close()

@app.delete('/api/admin/announcements/<aid>')
@require_admin
def admin_delete_announcement(aid):
    conn = get_db()
    try:
        conn.execute("DELETE FROM announcements WHERE id=?", (aid,))
        conn.execute("DELETE FROM announcement_reads WHERE announcement_id=?", (aid,))
        _audit(conn, 'admin', 'announce-delete', target=aid)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.get('/api/admin/deal-requests')
@require_admin
def admin_deal_requests():
    conn = get_db()
    rows = conn.execute("SELECT * FROM deal_requests ORDER BY COALESCE(resolved_at, created_at) DESC, created_at DESC").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.post('/api/admin/deal-requests/<rid>/resolve')
@require_admin
def admin_resolve_deal(rid):
    note = ((request.get_json() or {}).get('admin_note') or '').strip()
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM deal_requests WHERE id=?", (rid,)).fetchone()
        if not row: return jsonify({'error': 'Not found.'}), 404
        conn.execute("UPDATE deal_requests SET status='resolved', admin_note=?, resolved_at=? WHERE id=?",
                     (note, time.time(), rid))
        _audit(conn, 'admin', 'deal-resolve', target=rid, payload=note)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
    print("=" * 62)
    print("  Mobilearn — running")
    print("=" * 62)
    print(f"  DB file  :  {DB_PATH}")
    print(f"  Homepage :  http://localhost:{PORT}")
    print(f"  Admin    :  http://localhost:{PORT}/#/admin")
    print("  Admin login : admin / mobilearn2025")
    print("  Demo member : amara / amara123")
    print("=" * 62)
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
