"""
main.py — Servidor Flask · Quiniela Mundial 2026
================================================
Estructura del proyecto:
    application_word/
    ├── static/
    │   └── index.html        ← HTML de la app (copiar aquí)
    ├── main.py
    └── mundial2026.db        ← se crea automáticamente

Instalar dependencias:
    pip install flask flask-cors requests werkzeug

Ejecutar:
    python main.py   →  http://localhost:5000
"""

import os, sqlite3, uuid, random, secrets
from datetime import datetime, timezone, timedelta
from functools import wraps
import requests
from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# ─── Config ───────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, 'static')
DB_PATH    = os.path.join(BASE_DIR, 'mundial2026.db')

# LibreTranslate — cambia a tu instancia local si la tienes
LIBRETRANSLATE_URL = 'https://libretranslate.com/translate'

# Contraseña del admin global (para ingresar resultados)
GLOBAL_ADMIN_PASS  = 'admin2026'

# Horas antes del primer partido de cada jornada en que se bloquean pronósticos (Tipo B)
JORNADA_LOCK_HOURS = 4

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path='/static')
CORS(app)


# ═════════════════════════════════════════════════════════════════════════════
# BASE DE DATOS
# ═════════════════════════════════════════════════════════════════════════════

def get_db():
    db = getattr(g, '_db', None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, '_db', None)
    if db: db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id         TEXT PRIMARY KEY,
        username   TEXT NOT NULL UNIQUE COLLATE NOCASE,
        pw_hash    TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token      TEXT PRIMARY KEY,
        user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL
    );

    -- game_type: 'A' = pronóstico completo, 'B' = por jornada
    CREATE TABLE IF NOT EXISTS games (
        id         TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        code       TEXT NOT NULL UNIQUE,
        owner_id   TEXT NOT NULL REFERENCES users(id),
        game_type  TEXT NOT NULL DEFAULT 'A' CHECK(game_type IN ('A','B')),
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS game_members (
        game_id          TEXT NOT NULL REFERENCES games(id) ON DELETE CASCADE,
        user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        joined_at        TEXT NOT NULL,
        groups_submitted INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (game_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS predictions (
        game_id    TEXT NOT NULL REFERENCES games(id) ON DELETE CASCADE,
        user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        match_id   TEXT NOT NULL,
        match_type TEXT NOT NULL CHECK(match_type IN ('group','knockout')),
        home_score INTEGER,
        away_score INTEGER,
        home_team  TEXT,
        away_team  TEXT,
        saved_at   TEXT NOT NULL,
        PRIMARY KEY (game_id, user_id, match_id)
    );

    CREATE TABLE IF NOT EXISTS results (
        match_id   TEXT PRIMARY KEY,
        match_type TEXT NOT NULL CHECK(match_type IN ('group','knockout')),
        home_score INTEGER NOT NULL,
        away_score INTEGER NOT NULL,
        home_team  TEXT,
        away_team  TEXT,
        updated_at TEXT NOT NULL
    );
    """)
    db.commit()
    db.close()


# ─── Helpers ──────────────────────────────────────────────────────────────────
def ok(data=None):      return jsonify({"ok": True,  "data": data}), 200
def err(msg, code=400): return jsonify({"ok": False, "error": msg}), code
def now_iso():          return datetime.now(timezone.utc).isoformat()
def new_id():           return uuid.uuid4().hex[:20]
def gen_code():
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return ''.join(random.choices(chars, k=6))

def is_jornada_locked(match_date_str):
    """True si la jornada ya está bloqueada (< JORNADA_LOCK_HOURS antes del primer partido)."""
    try:
        first = datetime.strptime(match_date_str, '%Y-%m-%d').replace(
            hour=18, minute=0, tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= first - timedelta(hours=JORNADA_LOCK_HOURS)
    except Exception:
        return False


# ─── Auth middleware ───────────────────────────────────────────────────────────
def get_current_user():
    token = request.headers.get('X-Token', '').strip()
    if not token: return None
    row = get_db().execute(
        "SELECT s.user_id, u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?",
        (token,)
    ).fetchone()
    return dict(row) if row else None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user: return err('No autenticado', 401)
        g.user = user
        return f(*args, **kwargs)
    return decorated

def verify_admin():
    # Accept password from header (preferred) or JSON body field
    pw = (request.headers.get('X-Admin-Pass') or '').strip()
    if not pw:
        try:
            pw = (request.get_json(force=True, silent=True) or {}).get('adminPass','')
        except Exception:
            pw = ''
    return pw.strip() == GLOBAL_ADMIN_PASS


# ═════════════════════════════════════════════════════════════════════════════
# STATIC
# ═════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return send_from_directory(STATIC_DIR, 'index.html')


# ═════════════════════════════════════════════════════════════════════════════
# AUTH  /api/auth/*
# ═════════════════════════════════════════════════════════════════════════════

@app.route('/api/auth/register', methods=['POST'])
def register():
    body     = request.get_json(force=True) or {}
    username = (body.get('username') or '').strip()
    password = body.get('password') or ''
    if not username or not password:
        return err('Usuario y contraseña son requeridos')
    if len(username) < 3:
        return err('El usuario debe tener mínimo 3 caracteres')
    if len(password) < 4:
        return err('La contraseña debe tener mínimo 4 caracteres')
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        return err('Ese nombre de usuario ya está en uso')
    uid   = new_id()
    token = secrets.token_hex(32)
    db.execute("INSERT INTO users(id,username,pw_hash,created_at) VALUES(?,?,?,?)",
               (uid, username, generate_password_hash(password), now_iso()))
    db.execute("INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)",
               (token, uid, now_iso()))
    db.commit()
    return ok({'token': token, 'userId': uid, 'username': username})


@app.route('/api/auth/login', methods=['POST'])
def login():
    body     = request.get_json(force=True) or {}
    username = (body.get('username') or '').strip()
    password = body.get('password') or ''
    if not username or not password:
        return err('Usuario y contraseña son requeridos')
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user or not check_password_hash(user['pw_hash'], password):
        return err('Usuario o contraseña incorrectos')
    token = secrets.token_hex(32)
    db.execute("INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)",
               (token, user['id'], now_iso()))
    db.commit()
    return ok({'token': token, 'userId': user['id'], 'username': user['username']})


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    token = request.headers.get('X-Token', '')
    get_db().execute("DELETE FROM sessions WHERE token=?", (token,))
    get_db().commit()
    return ok()


# ═════════════════════════════════════════════════════════════════════════════
# GAMES  /api/games
# ═════════════════════════════════════════════════════════════════════════════

def build_game(row, db, viewer_id=None):
    gid     = row['id']
    members = db.execute(
        """SELECT gm.user_id, u.username, gm.joined_at, gm.groups_submitted
           FROM game_members gm JOIN users u ON u.id=gm.user_id
           WHERE gm.game_id=? ORDER BY gm.joined_at""", (gid,)
    ).fetchall()
    return {
        'id':        gid,
        'name':      row['name'],
        'code':      row['code'],
        'ownerId':   row['owner_id'],
        'gameType':  row['game_type'],
        'createdAt': row['created_at'],
        'members':   [{'userId': m['user_id'], 'username': m['username'],
                       'joinedAt': m['joined_at'],
                       'groupsSubmitted': bool(m['groups_submitted'])}
                      for m in members],
        'isMember':  any(m['user_id'] == viewer_id for m in members) if viewer_id else False,
        'isOwner':   row['owner_id'] == viewer_id if viewer_id else False,
    }


@app.route('/api/games', methods=['GET'])
@require_auth
def get_games():
    uid = g.user['user_id']
    db  = get_db()
    rows = db.execute(
        """SELECT DISTINCT gs.* FROM games gs
           LEFT JOIN game_members gm ON gm.game_id=gs.id AND gm.user_id=?
           WHERE gs.owner_id=? OR gm.user_id=?
           ORDER BY gs.created_at DESC""",
        (uid, uid, uid)
    ).fetchall()
    return ok([build_game(r, db, uid) for r in rows])


@app.route('/api/games', methods=['POST'])
@require_auth
def create_game():
    body      = request.get_json(force=True) or {}
    name      = (body.get('name') or '').strip()
    game_type = (body.get('gameType') or 'A').upper()
    if not name: return err('name es requerido')
    if game_type not in ('A','B'): return err('gameType debe ser A o B')
    uid  = g.user['user_id']
    db   = get_db()
    gid  = new_id()
    code = gen_code()
    while db.execute("SELECT 1 FROM games WHERE code=?", (code,)).fetchone():
        code = gen_code()
    db.execute("INSERT INTO games(id,name,code,owner_id,game_type,created_at) VALUES(?,?,?,?,?,?)",
               (gid, name, code, uid, game_type, now_iso()))
    db.execute("INSERT INTO game_members(game_id,user_id,joined_at,groups_submitted) VALUES(?,?,?,0)",
               (gid, uid, now_iso()))
    db.commit()
    row = db.execute("SELECT * FROM games WHERE id=?", (gid,)).fetchone()
    return ok(build_game(row, db, uid))


@app.route('/api/games/<game_id>', methods=['DELETE'])
@require_auth
def delete_game(game_id):
    uid = g.user['user_id']
    db  = get_db()
    row = db.execute("SELECT owner_id FROM games WHERE id=?", (game_id,)).fetchone()
    if not row: return err('Partida no encontrada', 404)
    if row['owner_id'] != uid: return err('Solo el creador puede eliminar la partida', 403)
    db.execute("DELETE FROM games WHERE id=?", (game_id,))
    db.commit()
    return ok()


@app.route('/api/games/<game_id>/join', methods=['POST'])
@require_auth
def join_game(game_id):
    uid = g.user['user_id']
    db  = get_db()
    row = db.execute("SELECT * FROM games WHERE id=?", (game_id,)).fetchone()
    if not row: return err('Partida no encontrada', 404)
    if not db.execute("SELECT 1 FROM game_members WHERE game_id=? AND user_id=?",
                      (game_id, uid)).fetchone():
        db.execute("INSERT INTO game_members(game_id,user_id,joined_at,groups_submitted) VALUES(?,?,?,0)",
                   (game_id, uid, now_iso()))
        db.commit()
        row = db.execute("SELECT * FROM games WHERE id=?", (game_id,)).fetchone()
    return ok(build_game(row, db, uid))


@app.route('/api/games/bycode/<code>', methods=['GET'])
def game_by_code(code):
    db  = get_db()
    row = db.execute("SELECT * FROM games WHERE code=?", (code.upper(),)).fetchone()
    if not row: return err('Partida no encontrada', 404)
    user = get_current_user()
    uid  = user['user_id'] if user else None
    return ok(build_game(row, db, uid))


# ═════════════════════════════════════════════════════════════════════════════
# PREDICTIONS  /api/predictions/<game_id>/<user_id>
# ═════════════════════════════════════════════════════════════════════════════

@app.route('/api/predictions/<game_id>/<user_id>', methods=['GET'])
@require_auth
def get_predictions(game_id, user_id):
    viewer_id = g.user['user_id']
    db        = get_db()

    # El viewer debe ser miembro de la partida
    if not db.execute("SELECT 1 FROM game_members WHERE game_id=? AND user_id=?",
                      (game_id, viewer_id)).fetchone():
        return err('No eres miembro de esta partida', 403)

    member = db.execute(
        "SELECT groups_submitted FROM game_members WHERE game_id=? AND user_id=?",
        (game_id, user_id)
    ).fetchone()
    if not member: return err('Participante no encontrado en la partida', 404)

    game = db.execute("SELECT game_type FROM games WHERE id=?", (game_id,)).fetchone()
    if not game: return err('Partida no encontrada', 404)

    rows = db.execute(
        "SELECT match_id,match_type,home_score,away_score,home_team,away_team "
        "FROM predictions WHERE game_id=? AND user_id=?",
        (game_id, user_id)
    ).fetchall()

    gm, km = {}, {}
    for r in rows:
        e = {'home': r['home_score'], 'away': r['away_score']}
        if r['match_type'] == 'group':
            gm[r['match_id']] = e
        else:
            e['homeTeam'] = r['home_team'] or ''
            e['awayTeam'] = r['away_team'] or ''
            km[r['match_id']] = e

    return ok({
        'groupMatches':    gm,
        'knockoutMatches': km,
        'groupsSubmitted': bool(member['groups_submitted']),
        'gameType':        game['game_type'],
        'canEdit':         viewer_id == user_id,
    })


@app.route('/api/predictions/<game_id>', methods=['POST'])
@require_auth
def save_predictions(game_id):
    """
    Guarda pronósticos. Solo el propio usuario puede guardar los suyos.
    Body: {
        groupMatches:    {matchId: {home, away}},
        knockoutMatches: {matchId: {home, away, homeTeam, awayTeam}},
        submitGroups: false,          ← Tipo A: bloquea grupos permanentemente
        matchDates: {matchId: date}   ← Tipo B: para verificar lock por jornada
    }
    """
    uid    = g.user['user_id']
    db     = get_db()

    member = db.execute(
        "SELECT groups_submitted FROM game_members WHERE game_id=? AND user_id=?",
        (game_id, uid)
    ).fetchone()
    if not member: return err('No eres miembro de esta partida', 403)

    game = db.execute("SELECT game_type FROM games WHERE id=?", (game_id,)).fetchone()
    if not game: return err('Partida no encontrada', 404)

    body          = request.get_json(force=True) or {}
    gm            = body.get('groupMatches',    {}) or {}
    km            = body.get('knockoutMatches', {}) or {}
    submit_groups = bool(body.get('submitGroups', False))
    match_dates   = body.get('matchDates', {}) or {}
    ts            = now_iso()

    # Tipo A: no modificar grupos si ya fueron enviados
    if game['game_type'] == 'A' and member['groups_submitted'] and gm:
        return err('Los pronósticos de grupos ya fueron enviados', 403)

    skipped = []
    for match_id, scores in gm.items():
        h = scores.get('home'); a = scores.get('away')
        if h is None or a is None: continue
        if game['game_type'] == 'B':
            mdate = match_dates.get(match_id)
            if mdate and is_jornada_locked(mdate):
                skipped.append(match_id); continue
        db.execute("""
            INSERT INTO predictions(game_id,user_id,match_id,match_type,home_score,away_score,saved_at)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(game_id,user_id,match_id)
            DO UPDATE SET home_score=excluded.home_score,away_score=excluded.away_score,saved_at=excluded.saved_at
        """, (game_id, uid, match_id, 'group', int(h), int(a), ts))

    # Tipo A: solo permite eliminatoria si grupos ya están enviados
    if km and game['game_type'] == 'A' and not member['groups_submitted']:
        return err('Envía tus pronósticos de grupos antes de acceder a la eliminatoria', 403)

    for match_id, scores in km.items():
        h  = scores.get('home'); a = scores.get('away')
        ht = scores.get('homeTeam', '') or ''
        at = scores.get('awayTeam', '') or ''
        if game['game_type'] == 'B':
            mdate = match_dates.get(match_id)
            if mdate and is_jornada_locked(mdate):
                skipped.append(match_id); continue
        db.execute("""
            INSERT INTO predictions(game_id,user_id,match_id,match_type,home_score,away_score,home_team,away_team,saved_at)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(game_id,user_id,match_id)
            DO UPDATE SET home_score=excluded.home_score,away_score=excluded.away_score,
                home_team=excluded.home_team,away_team=excluded.away_team,saved_at=excluded.saved_at
        """, (game_id, uid, match_id, 'knockout',
              int(h) if h not in (None,'') else None,
              int(a) if a not in (None,'') else None,
              ht, at, ts))

    if submit_groups and game['game_type'] == 'A':
        db.execute("UPDATE game_members SET groups_submitted=1 WHERE game_id=? AND user_id=?",
                   (game_id, uid))

    db.commit()
    return ok({'skipped': skipped, 'groupsSubmitted': submit_groups or bool(member['groups_submitted'])})


# ═════════════════════════════════════════════════════════════════════════════
# RESULTADOS  /api/results  (admin global)
# ═════════════════════════════════════════════════════════════════════════════

@app.route('/api/results', methods=['GET'])
def get_results():
    db   = get_db()
    rows = db.execute(
        "SELECT match_id,match_type,home_score,away_score,home_team,away_team FROM results"
    ).fetchall()
    gm, km = {}, {}
    for r in rows:
        e = {'home': r['home_score'], 'away': r['away_score']}
        if r['match_type'] == 'group':
            gm[r['match_id']] = e
        else:
            e['homeTeam'] = r['home_team'] or ''
            e['awayTeam'] = r['away_team'] or ''
            km[r['match_id']] = e
    return ok({'groupMatches': gm, 'knockoutMatches': km})


@app.route('/api/results', methods=['POST'])
def save_results():
    if not verify_admin(): return err('No autorizado', 403)
    body    = request.get_json(force=True) or {}
    matches = body.get('matches', []) or []
    db      = get_db()
    for m in matches:
        mid  = m.get('matchId');  mtyp = m.get('matchType','group')
        h    = m.get('home');     a    = m.get('away')
        ht   = m.get('homeTeam','') or ''; at = m.get('awayTeam','') or ''
        if not mid or h is None or a is None: continue
        db.execute("""
            INSERT INTO results(match_id,match_type,home_score,away_score,home_team,away_team,updated_at)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(match_id) DO UPDATE SET
                home_score=excluded.home_score,away_score=excluded.away_score,
                home_team=excluded.home_team,away_team=excluded.away_team,updated_at=excluded.updated_at
        """, (mid, mtyp, int(h), int(a), ht, at, now_iso()))
    if matches:
        db.commit()
    return ok({'saved': len([m for m in matches if m.get('matchId')])})


@app.route('/api/results', methods=['DELETE'])
def delete_results():
    if not verify_admin(): return err('No autorizado', 403)
    body      = request.get_json(force=True) or {}
    match_ids = body.get('matchIds', []) or []
    if not match_ids: return err('matchIds es requerido')
    db = get_db()
    db.executemany("DELETE FROM results WHERE match_id=?", [(m,) for m in match_ids])
    db.commit()
    return ok()


# ═════════════════════════════════════════════════════════════════════════════
# JORNADA STATUS  /api/jornada-status
# ═════════════════════════════════════════════════════════════════════════════

@app.route('/api/jornada-status', methods=['GET'])
def jornada_status():
    dates = [
        '2026-06-11','2026-06-12','2026-06-13','2026-06-14','2026-06-15',
        '2026-06-16','2026-06-17','2026-06-18','2026-06-19','2026-06-20',
        '2026-06-21','2026-06-22','2026-06-23','2026-06-24','2026-06-25',
        '2026-06-28','2026-06-29','2026-06-30','2026-07-01','2026-07-02',
        '2026-07-03','2026-07-04','2026-07-05','2026-07-08','2026-07-09',
        '2026-07-10','2026-07-11','2026-07-14','2026-07-15','2026-07-16',
        '2026-07-17','2026-07-18','2026-07-19',
    ]
    return ok({d: is_jornada_locked(d) for d in dates})


# ═════════════════════════════════════════════════════════════════════════════
# TRADUCCIÓN  /api/translate  (proxy hacia LibreTranslate)
# ═════════════════════════════════════════════════════════════════════════════

@app.route('/api/translate', methods=['POST'])
def translate():
    body   = request.get_json(force=True) or {}
    q      = body.get('q', '')
    source = body.get('source', 'es')
    target = body.get('target', 'en')

    if not q:
        return ok({'translatedText': ''})

    try:
        resp = requests.post(
            LIBRETRANSLATE_URL,
            json={'q': q, 'source': source, 'target': target, 'format': 'text'},
            timeout=3
        )
        if resp.ok:
            return ok({'translatedText': resp.json().get('translatedText', q)})
    except Exception:
        pass

    return ok({'translatedText': q})   # silently fall back to original


# ─── Arranque ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    print(f"✅  BD lista : {DB_PATH}")
    print(f"🌐  Servidor : http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
